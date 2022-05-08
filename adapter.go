package datastoreadapter

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"strings"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/casbin/casbin/model"
	"github.com/casbin/casbin/persist"
)

const casbinKind = "casbin"

// CasbinRule represents a rule in Casbin.
type CasbinRule struct {
	PType string `datastore:"ptype"`
	V0    string `datastore:"v0"`
	V1    string `datastore:"v1"`
	V2    string `datastore:"v2"`
	V3    string `datastore:"v3"`
	V4    string `datastore:"v4"`
	V5    string `datastore:"v5"`
}

// String version of the Casbin rule (CSV basically). Usable as a database key
func (cr *CasbinRule) String() string {
	res := ""

	appendOrTerminate := func(currentStr, strToAdd string) (string, bool) {
		tmp := strings.TrimSpace(strToAdd)
		if tmp == "" {
			return currentStr, false
		} else {
			if currentStr == "" {
				return tmp, true
			} else {
				return currentStr + "," + tmp, true
			}
		}
	}

	res, added := appendOrTerminate(res, cr.PType)
	if !added {
		return res
	}

	res, added = appendOrTerminate(res, cr.V0)
	if !added {
		return res
	}

	res, added = appendOrTerminate(res, cr.V1)
	if !added {
		return res
	}

	res, added = appendOrTerminate(res, cr.V2)
	if !added {
		return res
	}

	res, added = appendOrTerminate(res, cr.V3)
	if !added {
		return res
	}

	res, added = appendOrTerminate(res, cr.V4)
	if !added {
		return res
	}

	res, added = appendOrTerminate(res, cr.V5)
	return res
}

type Config struct {
	// Datastore kind name.
	// Optional. (Default: "casbin")
	Kind string
	// Datastore namespace.
	// Optional. (Default: "")
	Namespace string
	// Enables debug info to show database calls
	Debug bool

	// Configures max time for long running operations like LoadPolicy,
	// SavePolicy, RemoveFilteredPolicy. These may take seconds or minutes
	LoadSaveFilterDeadline time.Duration
	// Configures max time for quick incremental operations like AddPolicy
	// and RemovePolicy. These largely take under 150ms
	AddRemoveDeadline time.Duration
}

// adapter represents the GCP datastore adapter for policy storage.
type adapter struct {
	db     *datastore.Client
	config Config
}

// finalizer is the destructor for adapter.
func finalizer(a *adapter) {
	a.close()
}

func (a *adapter) close() {
	a.db.Close()
}

// NewAdapter is the constructor for Adapter. A valid datastore client must be provided.
func NewAdapter(db *datastore.Client) persist.Adapter {
	return NewAdapterWithConfig(db, Config{})
}

// NewAdapter is the constructor for Adapter. A valid datastore client must be provided.
func NewAdapterWithConfig(db *datastore.Client, config Config) persist.Adapter {
	// Initializing config default values
	if strings.TrimSpace(config.Kind) == "" {
		config.Kind = casbinKind
	}
	// Namespace default value of "" is okay
	// Debug default value of false is okay
	if config.LoadSaveFilterDeadline == 0 {
		config.LoadSaveFilterDeadline = time.Minute * 10
	}
	if config.AddRemoveDeadline == 0 {
		config.AddRemoveDeadline = time.Second * 30
	}

	a := &adapter{
		db:     db,
		config: config,
	}

	// Call the destructor when the object is released.
	runtime.SetFinalizer(a, finalizer)

	return a
}

// Datastore works most consistently if all data is inside an entity group.
// Kinda weird, but this is how you enable ACID (instead of eventual).
// See: https://cloud.google.com/datastore/docs/articles/balancing-strong-and-eventual-consistency-with-google-cloud-datastore#ancestor-query-and-entity-group
func (a *adapter) pseudoRootKey() *datastore.Key {
	key := datastore.IDKey(a.config.Kind, 1, nil)
	key.Namespace = a.config.Namespace
	return key
}

func (a *adapter) newQuery() *datastore.Query {
	return datastore.NewQuery(a.config.Kind).Namespace(a.config.Namespace).Filter("ptype >", "").Ancestor(a.pseudoRootKey())
}

func (a *adapter) LoadPolicy(model model.Model) error {
	var rules []*CasbinRule
	if a.config.Debug {
		log.Println("[LoadPolicy] called - getting all db entries")
	}

	ctx, cancel := context.WithTimeout(
		context.Background(), a.config.LoadSaveFilterDeadline)
	defer cancel()
	query := a.newQuery()
	_, err := a.db.GetAll(ctx, query, &rules)

	if err != nil {
		return err
	}

	for _, l := range rules {
		loadPolicyLine(*l, model)
	}

	return nil
}

func (a *adapter) SavePolicy(model model.Model) error {
	ctx, cancel := context.WithTimeout(
		context.Background(), a.config.LoadSaveFilterDeadline)
	defer cancel()
	if a.config.Debug {
		log.Println("[SavePolicy] called")
	}

	// Drop all casbin entities
	keys, err := a.db.GetAll(ctx, a.newQuery().KeysOnly(), nil)
	if err != nil {
		return err
	}
	if a.config.Debug {
		log.Println("[SavePolicy] keys to drop:", keys)
	}

	var lines []*CasbinRule

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, &line)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, &line)
		}
	}

	ancestor := a.pseudoRootKey()
	_, err = a.db.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		if err = tx.DeleteMulti(keys); err != nil {
			return err
		}
		if a.config.Debug {
			log.Println("[SavePolicy] keys deleted")
		}

		for _, line := range lines {
			name := line.String()
			key := datastore.NameKey(a.config.Kind, name, ancestor)
			key.Namespace = a.config.Namespace
			_, err := tx.Put(key, line)
			if err != nil {
				return err
			}
		}

		return nil
	})

	return err
}

func (a *adapter) AddPolicy(sec string, ptype string, rule []string) error {
	ctx, cancel := context.WithTimeout(
		context.Background(), a.config.AddRemoveDeadline)
	defer cancel()
	line := savePolicyLine(ptype, rule)

	name := line.String()
	key := datastore.NameKey(a.config.Kind, name, a.pseudoRootKey())
	key.Namespace = a.config.Namespace

	if a.config.Debug {
		log.Println("[AddPolicy] called:", name)
	}

	_, err := a.db.Put(ctx, key, &line)
	return err
}

func (a *adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	ctx, cancel := context.WithTimeout(
		context.Background(), a.config.AddRemoveDeadline)
	defer cancel()

	line := savePolicyLine(ptype, rule)
	name := line.String()
	key := datastore.NameKey(a.config.Kind, name, a.pseudoRootKey())

	if a.config.Debug {
		log.Println("[RemovePolicy] called:", name)
	}

	return a.db.Delete(ctx, key)
}

func (a *adapter) RemoveFilteredPolicy(sec string, ptype string,
	fieldIndex int, fieldValues ...string) error {

	if a.config.Debug {
		log.Println("[RemoveFilteredPolicy] called")
	}

	ctx, cancel := context.WithTimeout(
		context.Background(), a.config.LoadSaveFilterDeadline)
	defer cancel()

	var rules []*CasbinRule

	selector := make(map[string]interface{})
	selector["ptype"] = ptype

	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		if fieldValues[0-fieldIndex] != "" {
			selector["v0"] = fieldValues[0-fieldIndex]
		}
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		if fieldValues[1-fieldIndex] != "" {
			selector["v1"] = fieldValues[1-fieldIndex]
		}
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		if fieldValues[2-fieldIndex] != "" {
			selector["v2"] = fieldValues[2-fieldIndex]
		}
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		if fieldValues[3-fieldIndex] != "" {
			selector["v3"] = fieldValues[3-fieldIndex]
		}
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		if fieldValues[4-fieldIndex] != "" {
			selector["v4"] = fieldValues[4-fieldIndex]
		}
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		if fieldValues[5-fieldIndex] != "" {
			selector["v5"] = fieldValues[5-fieldIndex]
		}
	}

	query := a.newQuery()
	for k, v := range selector {
		query = query.Filter(fmt.Sprintf("%s =", k), v)
	}

	keys, err := a.db.GetAll(ctx, query, &rules)
	if err != nil {
		switch err {
		case datastore.ErrNoSuchEntity:
			return nil
		default:
			return err
		}
	}

	return a.db.DeleteMulti(ctx, keys)
}

func savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{
		PType: ptype,
	}

	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return line
}

func loadPolicyLine(line CasbinRule, model model.Model) {
	key := line.PType
	sec := key[:1]

	tokens := []string{}
	if line.V0 != "" {
		tokens = append(tokens, line.V0)
	} else {
		goto LineEnd
	}

	if line.V1 != "" {
		tokens = append(tokens, line.V1)
	} else {
		goto LineEnd
	}

	if line.V2 != "" {
		tokens = append(tokens, line.V2)
	} else {
		goto LineEnd
	}

	if line.V3 != "" {
		tokens = append(tokens, line.V3)
	} else {
		goto LineEnd
	}

	if line.V4 != "" {
		tokens = append(tokens, line.V4)
	} else {
		goto LineEnd
	}

	if line.V5 != "" {
		tokens = append(tokens, line.V5)
	} else {
		goto LineEnd
	}

LineEnd:
	model[sec][key].Policy = append(model[sec][key].Policy, tokens)
}

package datastoreadapter

import (
	"cloud.google.com/go/datastore"
	"context"
	"github.com/casbin/casbin"
	"os"
	"testing"
)

var testProjectID = os.Getenv("TEST_CASBIN_DATASTORE_PROJECT_ID")

func getDatastore() *datastore.Client {
	ctx := context.Background()
	ds, err := datastore.NewClient(ctx, testProjectID)
	if err != nil {
		panic(err)
	}
	return ds
}

func testGetPolicy(t *testing.T, e *casbin.Enforcer, res [][]string) {
	myRes := e.GetPolicy()

	if !sameStringSlice(flat(res), flat(myRes)) {
		t.Error("Policy: ", myRes, ", supposed to be ", res)
	}

}

func flat(arr2D [][]string) []string {

	res := []string{}
	for _, arr := range arr2D {
		for _, e := range arr {
			res = append(res, e)
		}
	}

	return res
}

func sameStringSlice(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	// create a map of string -> int
	diff := make(map[string]int, len(x))
	for _, _x := range x {
		// 0 value for int is 0, so just increment a counter for the string
		diff[_x]++
	}
	for _, _y := range y {
		// If the string _y is not in diff bail out early
		if _, ok := diff[_y]; !ok {
			return false
		}
		diff[_y]--
		if diff[_y] == 0 {
			delete(diff, _y)
		}
	}
	if len(diff) == 0 {
		return true
	}
	return false
}

func initPolicy(t *testing.T) {
	// Because the DB is empty at first,
	// so we need to load the policy from the file adapter (.CSV) first.
	e := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")

	a := NewAdapter(getDatastore())
	// This is a trick to save the current policy to the DB.
	// We can't call e.SavePolicy() because the adapter in the enforcer is still the file adapter.
	// The current policy means the policy in the Casbin enforcer (aka in memory).
	err := a.SavePolicy(e.GetModel())
	if err != nil {
		panic(err)
	}

	// Clear the current policy.
	e.ClearPolicy()
	testGetPolicy(t, e, [][]string{})

	// Load the policy from DB.
	err = a.LoadPolicy(e.GetModel())
	if err != nil {
		panic(err)
	}
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func TestAdapter(t *testing.T) {
	initPolicy(t)

	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	a := NewAdapter(getDatastore())
	e := casbin.NewEnforcer("examples/rbac_model.conf", a)
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// AutoSave is enabled by default.
	// Now we disable it.
	e.EnableAutoSave(false)

	// Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
	// it doesn't affect the policy in the storage.
	e.AddPolicy("alice", "data1", "write")
	// Reload the policy from the storage to see the effect.
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	// This is still the original policy.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Now we enable the AutoSave.
	e.EnableAutoSave(true)

	// Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
	// but also affects the policy in the storage.
	e.AddPolicy("alice", "data1", "write")
	// Reload the policy from the storage to see the effect.
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	// The policy has a new rule: {"alice", "data1", "write"}.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data1", "write"}})

	// Remove the added rule.
	e.RemovePolicy("alice", "data1", "write")
	if err := a.RemovePolicy("p", "p", []string{"alice", "data1", "write"}); err != nil {
		t.Errorf("Expected RemovePolicy() to be successful; got %v", err)
	}
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Remove "data2_admin" related policy rules via a filter.
	// Two rules: {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"} are deleted.
	e.RemoveFilteredPolicy(0, "data2_admin")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})

	e.RemoveFilteredPolicy(1, "data1")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{{"bob", "data2", "write"}})

	e.RemoveFilteredPolicy(2, "write")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{})
}

func TestDeleteFilteredAdapter(t *testing.T) {
	a := NewAdapter(getDatastore())
	e := casbin.NewEnforcer("examples/rbac_tenant_service.conf", a)

	e.AddPolicy("domain1", "alice", "data3", "read", "accept", "service1")
	e.AddPolicy("domain1", "alice", "data3", "write", "accept", "service2")

	// Reload the policy from the storage to see the effect.
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	// The policy has a new rule: {"alice", "data1", "write"}.
	testGetPolicy(t, e, [][]string{{"domain1", "alice", "data3", "read", "accept", "service1"},
		{"domain1", "alice", "data3", "write", "accept", "service2"}})
	// test RemoveFiltered Policy with "" fileds
	e.RemoveFilteredPolicy(0, "domain1", "", "", "read")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{{"domain1", "alice", "data3", "write", "accept", "service2"}})

	e.RemoveFilteredPolicy(0, "domain1", "", "", "", "", "service2")
	if err := e.LoadPolicy(); err != nil {
		t.Errorf("Expected LoadPolicy() to be successful; got %v", err)
	}
	testGetPolicy(t, e, [][]string{})
}
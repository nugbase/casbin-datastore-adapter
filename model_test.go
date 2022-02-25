package datastoreadapter

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/casbin/casbin/model"
)

func TestSaveAndLoadModel(t *testing.T) {
	original, err := model.NewModelFromFile("examples/rbac_model.conf")
	if err != nil {
		t.Fatal(err)
	}

	db := getDatastore()
	config := Config{
		Namespace: "unittest",
	}

	if err = SaveModelWithConfig(db, "examples/rbac_model.conf", config); err != nil {
		t.Errorf("got %v, wants no error", err)
		return
	}

	actual, err := LoadModelWithConfig(db, config)
	if err != nil {
		t.Errorf("got %v, wants no error", err)
		return
	}

	s1 := modelToText(original)
	s2 := modelToText(actual)
	if s1 != s2 {
		t.Errorf("Loaded model is different")
	}
}

func TestSaveInvalidFile(t *testing.T) {
	db := getDatastore()
	config := Config{
		Namespace: "unittest",
	}

	err := SaveModelWithConfig(db, "examples/rbac_policy.csv", config)
	if err == nil {
		t.Errorf("got no error, wants an error")
		return
	}
}

func TestLoadModelFail(t *testing.T) {
	db := getDatastore()
	config := Config{
		Namespace: "unknown",
	}

	_, err := LoadModelWithConfig(db, config)
	if err == nil {
		t.Errorf("got no error, wants an error")
		return
	}
}

func modelToText(model model.Model) string {
	var lines []string
	for k, v := range model {
		for i, j := range v {
			lines = append(lines, fmt.Sprintf("%s.%s: %s", k, i, j.Value))
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

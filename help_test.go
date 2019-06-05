package gorbac

import (
	"errors"
	"testing"
)

var (
	pAll  = NewPermission("permission-all")
	pNone = NewPermission("permission-none")
)

func prepare(t *testing.T) *RBAC {

	rbac := New()
	rA.Assign(pA).Assign(pAll)
	rB.Assign(pB).Assign(pAll)
	rC.Assign(pC).Assign(pAll)

	assert(t, rbac.Add(rA))
	assert(t, rbac.Add(rB))
	assert(t, rbac.Add(rC))

	assert(t, rbac.SetParent("role-a", "role-b"))
	assert(t, rbac.SetParent("role-b", "role-c"))
	assert(t, rbac.SetParent("role-c", "role-a"))

	return rbac
}

func TestInheritanceCircle(t *testing.T) {
	rbac := prepare(t)

	if err := InheritanceCircle(rbac); err == nil {
		t.Fatal("There should be a circle inheritance.")
	} else {
		t.Log(err)
	}
}

func TestNoneInheritanceCircle(t *testing.T) {
	rbac := prepare(t)

	assert(t, rbac.RemoveParent("role-c", "role-a"))
	if err := InheritanceCircle(rbac); err != nil {
		t.Fatal(err)
	}
}

func TestAllGranted(t *testing.T) {
	rbac := prepare(t)

	assert(t, rbac.RemoveParent("role-c", "role-a"))

	// All roles have pAll
	roles := []string{"role-a", "role-b", "role-c"}
	if !AllGranted(rbac, roles, pAll, nil) {
		t.Errorf("All roles(%v) were expected having %s, but they weren't.", roles, pAll)
	}

	if AllGranted(rbac, roles, pA, nil) {
		t.Errorf("Not all roles(%v) were expected having %s, but they were.", roles, pA)
	}
}

func TestAnyGranted(t *testing.T) {
	rbac := prepare(t)
	assert(t, rbac.RemoveParent("role-c", "role-a"))

	// rA roles have pA
	roles := []string{"role-a", "role-b", "role-c"}
	if !AnyGranted(rbac, roles, pA, nil) {
		t.Errorf("One of roles(%v) was expected having %s, but it wasn't.", roles, pA)
	}

	if AnyGranted(rbac, roles, pNone, nil) {
		t.Errorf("None of roles(%v) were expected having %s, but it was.", roles, pNone)
	}

}

func TestWalkNil(t *testing.T) {
	rbac := prepare(t)

	if err := Walk(rbac, nil); err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
}

func TestWalkError(t *testing.T) {
	rbac := prepare(t)

	he := func(r Role, parents []string) error {
		return errors.New("expected error")
	}
	if err := Walk(rbac, he); err == nil {
		t.Errorf("Expected error, got nil")
	}
}

func TestWalk(t *testing.T) {
	rbac := prepare(t)

	h := func(r Role, parents []string) error {
		t.Logf("Role: %v", r.ID())
		permissions := make([]string, 0)
		for _, p := range r.Permissions() {
			permissions = append(permissions, p.ID())
		}
		t.Logf("Permission: %v", permissions)
		t.Logf("Parents: %v", parents)
		return nil
	}

	if err := Walk(rbac, h); err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if err := InheritanceCircle(rbac); err == nil {
		t.Fatal("There should be a circle inheritance.")
	} else {
		t.Log(err)
	}
}

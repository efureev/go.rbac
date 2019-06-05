package rbac

import (
	"testing"
)

func TestSimpleRole(t *testing.T) {
	rA := NewRole("role-a")
	if rA.ID() != "role-a" {
		t.Fatalf("[a] expected, but %s got", rA.ID())
	}
	rA.Assign(NewPermission("permission-a"))

	if !rA.Permit(NewPermission("permission-a")) {
		t.Fatal("[permission-a] should permit to rA")
	}
	/*if !rA.PermitOld(NewPermission("permission-a")) {
		t.Fatal("[permission-a] should permit to rA")
	}*/
	if len(rA.Permissions()) != 1 {
		t.Fatal("[a] should have one permission")
	}

	if err := rA.Revoke(NewPermission("permission-a")); err != nil {
		t.Fatal(err)
	}
	if rA.Permit(NewPermission("permission-a")) {
		t.Fatal("[permission-a] should not permit to rA")
	}
	/*if rA.PermitOld(NewPermission("permission-a")) {
		t.Fatal("[permission-a] should not permit to rA")
	}*/
	if len(rA.Permissions()) != 0 {
		t.Fatal("[a] should not have any permission")
	}

	if rA.Permit(nil) {
		t.Fatal("permission should not nil")
	}
}
/*
func BenchmarkSimpleRole_PermitOld(b *testing.B) {
	rA := NewRole("role-a")
	rA.Assign(NewPermission("permission-a"))
	np := NewPermission("permission-a")

	for i := 0; i < b.N; i++ {
		if !rA.PermitOld(np) {
			b.Fatal("[permission-a] should permit to rA")
		}
	}
}*/

func BenchmarkSimpleRole_Permit(b *testing.B) {
	rA := NewRole("role-a")
	rA.Assign(NewPermission("permission-a"))
	np := NewPermission("permission-a")

	for i := 0; i < b.N; i++ {
		if !rA.Permit(np) {
			b.Fatal("[permission-a] should permit to rA")
		}
	}
}

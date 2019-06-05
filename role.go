package gorbac

import "sync"

// Role is an interface.
// You should implement this interface for your own role structures.
type Role interface {
	ID() string
	Permit(Permission) bool
	Permissions() []Permission
}

// Roles is a map
type Roles map[string]Role

// NewRole is the default role factory function.
func NewRole(id string) *SimpleRole {
	role := &SimpleRole{
		IDStr:       id,
		permissions: make(Permissions),
	}

	return role
}

// SimpleRole is the default role implement.
// You can combine this struct into your own Role implement.
type SimpleRole struct {
	sync.RWMutex
	// IDStr is the identity of role
	IDStr       string `json:"id"`
	permissions Permissions
}

// ID returns the role's identity name.
func (role *SimpleRole) ID() string {
	return role.IDStr
}

// Assign a permission to the role.
func (role *SimpleRole) Assign(p Permission) *SimpleRole {
	role.Lock()
	role.permissions[p.ID()] = p
	role.Unlock()

	return role
}

// Permit returns true if the role has specific permission.
func (role *SimpleRole) Permit(p Permission) (res bool) {
	if p == nil {
		return false
	}

	role.RLock()

	if _, ok := role.permissions[p.ID()]; ok {
		res = true
	}

	role.RUnlock()
	return
}

// Revoke the specific permission.
func (role *SimpleRole) Revoke(p Permission) error {
	role.Lock()
	delete(role.permissions, p.ID())
	role.Unlock()
	return nil
}

// Permissions returns all permissions into a slice.
func (role *SimpleRole) Permissions() []Permission {
	role.RLock()
	result := make([]Permission, 0, len(role.permissions))
	for _, p := range role.permissions {
		result = append(result, p)
	}
	role.RUnlock()
	return result
}

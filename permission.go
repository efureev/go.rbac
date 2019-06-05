package rbac

import "strings"

// Permission exports `Id` and `Match`
type Permission interface {
	ID() string
	Match(Permission) bool
}

// Permissions is a map
type Permissions map[string]Permission

// SimplePermission only checks if the Ids are fully matching.
type SimplePermission struct {
	IDStr string
}

// NewPermission returns a Permission instance with `id`
func NewPermission(id string) Permission {
	return &SimplePermission{id}
}

// ID returns the identity of permission
func (p *SimplePermission) ID() string {
	return p.IDStr
}

// Match another permission
func (p *SimplePermission) Match(a Permission) bool {
	return p.IDStr == a.ID()
}

// DeepPermission firstly checks the Id of permission.
// If the Id is matched, it can be considered having the permission.
// Otherwise, it checks every layers of permission.
// A role which has an upper layer granted, will be granted sub-layers permissions.
type DeepPermission struct {
	IDStr string `json:"id"`
	Sep   string `json:"sep"`
}

// NewDeepPermission returns an instance of layered permission with `id`
func NewDeepPermission(id string) Permission {
	return &DeepPermission{id, ":"}
}

// ID returns the identity of permission
func (p *DeepPermission) ID() string {
	return p.IDStr
}

// Match another permission
func (p *DeepPermission) Match(a Permission) bool {
	if p.IDStr == a.ID() {
		return true
	}
	q, ok := a.(*DeepPermission)
	if !ok {
		return false
	}
	pLayers := strings.Split(p.IDStr, p.Sep)
	qLayers := strings.Split(q.IDStr, q.Sep)
	// layer counts of q should be less than that of p
	if len(pLayers) > len(qLayers) {
		return false
	}
	for k, pv := range pLayers {
		if pv != qLayers[k] {
			return false
		}
	}
	return true
}

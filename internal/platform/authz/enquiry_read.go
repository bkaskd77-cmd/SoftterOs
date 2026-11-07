package authz

import "time"

const CapabilityReadEnquiry Capability = "enquiries.read"

// CanReadAssignedEnquiries is a preflight on current trusted facts. An enquiry
// still requires the owning organization and exact current assignee to match.
func (c Context) CanReadAssignedEnquiries(at time.Time) bool {
	return c.actor.Human && c.validMembership(at) && c.hasCapability(CapabilityReadEnquiry)
}

// CanReadAssignedEnquiry takes the owner and current assignee from the
// authoritative record. It grants no reusable authorization.
func (c Context) CanReadAssignedEnquiry(ownerID, assigneeID string, at time.Time) bool {
	return c.CanReadAssignedEnquiries(at) && ownerID == c.activeOrganizationID &&
		assigneeID == c.membership.ID
}

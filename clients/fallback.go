package clients

// TriggerFallbackHolePunch sends an immediate hole punch to the exit nodes.
// Fork-only (TCP 443 fallback): used after switching between UDP and the
// relay so Gerbil and Pangolin learn the new source address quickly.
func (s *WireGuardService) TriggerFallbackHolePunch() {
	if s == nil || s.holePunchManager == nil {
		return
	}
	_ = s.holePunchManager.TriggerHolePunch()
	s.holePunchManager.ResetServerHolepunchInterval()
}

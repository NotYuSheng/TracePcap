import { AddressTabs } from '@/features/networkAddress/NetworkAddressConfigModal';
import { defaultSource } from '@/features/networkAddress/networkAddressService';

/**
 * The shared address defaults (#915 phase 4c): the subnet labels, internal/external ranges and
 * organisations every network starts from. A network adjusts them for itself from its page's
 * Addresses dialog; captures outside any network use these as they are.
 */
export function AddressDefaultsPanel() {
  return (
    <div style={{ fontSize: '0.85rem' }}>
      <p className="text-muted small">
        What every network starts from, and what captures outside any network use. A network can
        override, hide or add to these for itself from its page's <strong>Addresses</strong> button.
      </p>
      <AddressTabs source={defaultSource} idPrefix="address-defaults" />
    </div>
  );
}

// Contacts view — persistent address book (Phase 5.1)
import { useState, useEffect, useCallback } from 'react';
import { api } from '../api';
import { useStore } from '../store';

interface Contact {
  contact_id: number;
  label: string;
  identities: { identity_id: string; system: string; system_data: string; last_verified: string | null }[];
}

export function ContactsView() {
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [label, setLabel] = useState('');
  const [address, setAddress] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadContacts = useCallback(async () => {
    try {
      const res: any = await api.getContacts();
      setContacts(Array.isArray(res) ? res : (res.contacts || []));
    } catch (e: any) {
      setError(e.message);
    }
  }, []);

  useEffect(() => { loadContacts(); }, [loadContacts]);

  const addContact = async () => {
    if (!label || !address) return;
    setLoading(true);
    setError(null);
    try {
      await api.addContact(label, 'OnChain', address);
      setLabel('');
      setAddress('');
      await loadContacts();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const removeContact = async (contactId: number) => {
    try {
      await api.deleteContact(contactId);
      await loadContacts();
    } catch (e: any) {
      setError(e.message);
    }
  };

  return (
    <div className="p-4">
      <h2 className="text-lg font-semibold mb-4 text-accent">Contacts</h2>
      <div className="max-w-lg space-y-3">
        {error && <div className="text-red-400 text-sm mb-2">{error}</div>}
        <div className="bg-void-900 rounded-lg p-4 border border-void-700">
          <div className="text-sm text-gray-400 mb-3">Add new contact</div>
          <div className="space-y-2">
            <input
              type="text"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="Label"
              className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none"
            />
            <input
              type="text"
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              placeholder="Public key (hex)"
              className="w-full bg-void-800 border border-void-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:border-accent outline-none"
            />
            <button
              onClick={addContact}
              disabled={loading || !label || !address}
              className="bg-accent hover:bg-accent-hover text-white rounded-lg px-4 py-2 text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {loading ? 'Adding…' : 'Add Contact'}
            </button>
          </div>
        </div>
        {contacts.length === 0 ? (
          <div className="text-gray-400 text-sm">No contacts yet.</div>
        ) : (
          contacts.map((c) => (
            <div key={c.contact_id} className="bg-void-900 rounded-lg p-3 flex justify-between items-center border border-void-700">
              <div>
                <div className="text-sm text-gray-100">{c.label}</div>
                {c.identities.map((id, i) => (
                  <div key={i} className="text-xs font-mono text-gray-400">
                    {id.system}: {id.system_data.slice(0, 20)}…
                  </div>
                ))}
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => navigator.clipboard.writeText(c.identities[0]?.system_data || '')}
                  className="text-xs text-gray-400 hover:text-accent transition-colors"
                >
                  Copy
                </button>
                <button
                  onClick={() => removeContact(c.contact_id)}
                  className="text-xs text-red-400 hover:text-red-300 transition-colors"
                >
                  Delete
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
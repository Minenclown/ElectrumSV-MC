// Menu bar — top of window (ElectrumSV-style: File, Wallet, Tools, Help)
// Language selector in Help menu — persisted in localStorage
import { useState } from 'react';
import { useStore } from '../store';
import { useTranslation, type Language } from '../i18n';
import { ExportSeedDialog, ChangePasswordDialog, SignMessageDialog, VerifyMessageDialog, DeleteWalletDialog } from './WalletDialogs';

interface MenuItem {
  label: string;
  action?: () => void;
  separator?: boolean;
  disabled?: boolean;
}

interface Menu {
  label: string;
  items: MenuItem[];
}

type DialogType = 'exportSeed' | 'changePassword' | 'signMessage' | 'verifyMessage' | 'deleteWallet' | null;

export function MenuBar({ onCreateWallet, onDeleteWallet, onQuit }: {
  onCreateWallet?: () => void;
  onDeleteWallet?: () => void;
  onQuit?: () => void;
}) {
  const [openMenu, setOpenMenu] = useState<string | null>(null);
  const [activeDialog, setActiveDialog] = useState<DialogType>(null);
  const { activeWalletPath, walletName, setError } = useStore();
  const { t, language, setLanguage } = useTranslation();

  const handleAbout = () => {
    alert('ElectrumSV-Mc\nA lightweight BSV wallet.');
  };

  const languages: { code: Language; label: string; flag: string }[] = [
    { code: 'en', label: t.menu.english, flag: '🇬🇧' },
    { code: 'de', label: t.menu.german, flag: '🇩🇪' },
  ];

  const menus: Menu[] = [
    {
      label: t.menu.file,
      items: [
        { label: t.menu.newWallet, action: onCreateWallet },
        { label: t.menu.openWallet, action: onCreateWallet },
        { label: t.menu.closeWallet, action: onQuit, disabled: !activeWalletPath },
        { label: t.menu.quit, action: onQuit },
      ],
    },
    {
      label: t.menu.wallet,
      items: [
        { label: t.menu.deleteWallet, action: () => setActiveDialog('deleteWallet'), disabled: !activeWalletPath },
        { label: t.menu.changePassword, action: () => setActiveDialog('changePassword'), disabled: !activeWalletPath },
        { label: t.menu.exportSeed, action: () => setActiveDialog('exportSeed'), disabled: !activeWalletPath },
      ],
    },
    {
      label: t.menu.tools,
      items: [
        { label: t.menu.signMessage, action: () => setActiveDialog('signMessage') },
        { label: t.menu.verifyMessage, action: () => setActiveDialog('verifyMessage') },
      ],
    },
    {
      label: t.menu.help,
      items: [
        { label: t.menu.about, action: handleAbout },
        { label: t.menu.documentation, action: () => window.open('https://electrumsv.readthedocs.io/', '_blank') },
        { label: t.menu.language, separator: true },
        ...languages.map((lang) => ({
          label: `${lang.flag} ${lang.label}${language === lang.code ? ' ✓' : ''}`,
          action: () => setLanguage(lang.code),
        })),
      ],
    },
  ];

  return (
    <>
      <div className="flex bg-void-900 border-b border-void-700 text-sm select-none">
        {menus.map((menu) => (
          <div key={menu.label} className="relative">
            <button
              onClick={() => setOpenMenu(openMenu === menu.label ? null : menu.label)}
              className={`px-3 py-1.5 text-gray-400 hover:text-gray-100 hover:bg-void-800 transition-colors ${
                openMenu === menu.label ? 'bg-void-800 text-gray-100' : ''
              }`}
            >
              {menu.label}
            </button>
            {openMenu === menu.label && (
              <>
                <div className="fixed inset-0 z-10" onClick={() => setOpenMenu(null)} />
                <div className="absolute left-0 top-full z-20 bg-void-900 border border-void-700 rounded-lg shadow-xl py-1 min-w-48">
                  {menu.items.map((item, i) => (
                    item.separator ? (
                      <div key={i} className="border-t border-void-700 my-1 px-4 text-xs text-gray-500 pt-1">
                        {item.label}
                      </div>
                    ) : (
                      <button
                        key={i}
                        onClick={() => {
                          if (!item.disabled) {
                            item.action?.();
                          }
                          setOpenMenu(null);
                        }}
                        disabled={item.disabled}
                        className="w-full text-left px-4 py-1.5 text-sm text-gray-400 hover:text-gray-100 hover:bg-void-800 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                      >
                        {item.label}
                      </button>
                    )
                  ))}
                </div>
              </>
            )}
          </div>
        ))}
      </div>

      {/* Dialogs */}
      <ExportSeedDialog open={activeDialog === 'exportSeed'} onClose={() => setActiveDialog(null)} />
      <ChangePasswordDialog open={activeDialog === 'changePassword'} onClose={() => setActiveDialog(null)} />
      <SignMessageDialog open={activeDialog === 'signMessage'} onClose={() => setActiveDialog(null)} />
      <VerifyMessageDialog open={activeDialog === 'verifyMessage'} onClose={() => setActiveDialog(null)} />
      <DeleteWalletDialog
        open={activeDialog === 'deleteWallet'}
        onClose={() => setActiveDialog(null)}
        walletPath={activeWalletPath ?? ''}
        walletName={walletName ?? ''}
        onDeleted={() => {
          setError('Wallet deleted. Returning to landing page.');
          onQuit?.();
        }}
      />
    </>
  );
}
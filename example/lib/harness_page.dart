import 'dart:io';

import 'package:ebill_flutter_ffi/api/bill.dart' as bill_api;
import 'package:ebill_flutter_ffi/api/company.dart' as company_api;
import 'package:ebill_flutter_ffi/api/contact.dart' as contact_api;
import 'package:ebill_flutter_ffi/api/general.dart' as general_api;
import 'package:ebill_flutter_ffi/api/identity.dart' as identity_api;
import 'package:ebill_flutter_ffi/api/notification.dart' as notification_api;
import 'package:ebill_flutter_ffi/data/bill.dart' as bill_data;
import 'package:ebill_flutter_ffi/data/company.dart' as company_data;
import 'package:ebill_flutter_ffi/data/contact.dart' as contact_data;
import 'package:ebill_flutter_ffi/data/identity.dart' as identity_data;
import 'package:ebill_flutter_ffi/data/lib.dart' as data;
import 'package:flutter/material.dart';

import 'dev_config.dart';
import 'mappings.dart' as mappings;

class HarnessPage extends StatefulWidget {
  const HarnessPage({required this.dataDirectory, super.key});

  final String dataDirectory;

  @override
  State<HarnessPage> createState() => _HarnessPageState();
}

class _HarnessPageState extends State<HarnessPage> {
  final _console = <String>[];
  bool _busy = false;
  bool _notificationSubscribed = false;

  final _currency = TextEditingController(text: 'SAT');
  final _generalSearch = TextEditingController();

  final _filePath = TextEditingController();
  final _fileUploadId = TextEditingController();
  final _fileName = TextEditingController();
  final _blossomHash = TextEditingController();

  final _identityName = TextEditingController(text: 'Johanna Smith');
  final _identityEmail = TextEditingController(text: 'jsmith@example.com');
  final _identitySwitchNodeId = TextEditingController();
  final _identityConfirmationCode = TextEditingController();
  final _seedPhrase = TextEditingController();
  final _shareRecipientNodeId = TextEditingController();

  final _contactNodeId = TextEditingController();
  final _contactName = TextEditingController(text: 'Test Contact');
  final _contactEmail = TextEditingController(text: 'text@example.com');
  final _contactSearch = TextEditingController();
  final _pendingShareId = TextEditingController();
  final _pendingReceiverNodeId = TextEditingController();

  final _companyId = TextEditingController();
  final _companyName = TextEditingController(text: 'hayek Ltd');
  final _companyEmail = TextEditingController(text: 'test@example.com');
  final _companySignatoryNodeId = TextEditingController();
  final _companySignatoryEmail = TextEditingController(text: 'signatory@example.com');
  final _companyConfirmationCode = TextEditingController();

  final _billId = TextEditingController();
  final _billCounterpartyNodeId = TextEditingController();
  final _billEndorseeNodeId = TextEditingController();
  final _billSum = TextEditingController(text: '9000');
  final _actionSum = TextEditingController(text: '500');
  final _deadlineDays = TextEditingController(text: '3');
  final _billSearch = TextEditingController();
  final _mintNodeId = TextEditingController(text: defaultMintNodeId);
  final _mintRequestId = TextEditingController();
  final _mintPaymentAddress = TextEditingController();
  final _courtNodeId = TextEditingController();
  final _btcAddress = TextEditingController();
  final _btcSourceAddress = TextEditingController();
  final _btcDestinationAddress = TextEditingController();
  final _btcFee = TextEditingController(text: '1000');

  final _notificationNodeIds = TextEditingController();
  final _notificationId = TextEditingController();
  final _resendQueueId = TextEditingController();

  Iterable<TextEditingController> get _controllers => [
        _currency,
        _generalSearch,
        _filePath,
        _fileUploadId,
        _fileName,
        _blossomHash,
        _identityName,
        _identityEmail,
        _identitySwitchNodeId,
        _identityConfirmationCode,
        _seedPhrase,
        _shareRecipientNodeId,
        _contactNodeId,
        _contactName,
        _contactEmail,
        _contactSearch,
        _pendingShareId,
        _pendingReceiverNodeId,
        _companyId,
        _companyName,
        _companyEmail,
        _companySignatoryNodeId,
        _companySignatoryEmail,
        _companyConfirmationCode,
        _billId,
        _billCounterpartyNodeId,
        _billEndorseeNodeId,
        _billSum,
        _actionSum,
        _deadlineDays,
        _billSearch,
        _mintNodeId,
        _mintRequestId,
        _mintPaymentAddress,
        _courtNodeId,
        _btcAddress,
        _btcSourceAddress,
        _btcDestinationAddress,
        _btcFee,
        _notificationNodeIds,
        _notificationId,
        _resendQueueId,
      ];

  @override
  void dispose() {
    for (final controller in _controllers) {
      controller.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Bitcredit E-Bill FFI Test Harness'),
        actions: [
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12),
            child: Center(
              child: Text(
                _busy ? 'running...' : 'ready',
                style: Theme.of(context).textTheme.labelLarge,
              ),
            ),
          ),
        ],
      ),
      body: LayoutBuilder(
        builder: (context, constraints) {
          if (constraints.maxWidth < 1050) {
            return Column(
              children: [
                Expanded(flex: 3, child: _controls()),
                const Divider(height: 1),
                Expanded(flex: 2, child: _consolePanel()),
              ],
            );
          }
          return Row(
            children: [
              Expanded(flex: 7, child: _controls()),
              const VerticalDivider(width: 1),
              Expanded(flex: 4, child: _consolePanel()),
            ],
          );
        },
      ),
    );
  }

  Widget _controls() {
    return ListView(
      padding: const EdgeInsets.all(12),
      children: [
      Card(
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
            Expanded(
              child: SelectableText(
                'Data directory: ${widget.dataDirectory}',
                ),
              ),
            const SizedBox(width: 16),
            FilledButton.tonalIcon(
              onPressed: _busy ? null : _resetState,
              icon: const Icon(Icons.delete_forever),
              label: const Text('Reset state'),
              ),
            ],
            ),
          ),
        ),
        _generalSection(),
        _uploadSection(),
        _identitySection(),
        _contactSection(),
        _contactShareSection(),
        _companySection(),
        _billCreationSection(),
        _billActionSection(),
        _billDevMintBtcSection(),
        _notificationSection(),
        _resendQueueSection(),
      ],
    );
  }

  Widget _consolePanel() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 10, 8, 6),
          child: Row(
            children: [
              Text('Result / error console', style: Theme.of(context).textTheme.titleMedium),
              const Spacer(),
              TextButton(
                onPressed: () => setState(_console.clear),
                child: const Text('Clear'),
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        Expanded(
          child: _console.isEmpty
              ? const Center(child: Text('Run an action.'))
              : ListView.builder(
                  reverse: true,
                  padding: const EdgeInsets.all(12),
                  itemCount: _console.length,
                  itemBuilder: (context, index) {
                    final entry = _console[_console.length - 1 - index];
                    return Padding(
                      padding: const EdgeInsets.only(bottom: 14),
                      child: SelectableText(
                        entry,
                        style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                      ),
                    );
                  },
                ),
        ),
      ],
    );
  }

  Widget _section(String title, List<Widget> children, {bool initiallyExpanded = false}) {
    return Card(
      child: ExpansionTile(
        initiallyExpanded: initiallyExpanded,
        title: Text(title),
        childrenPadding: const EdgeInsets.fromLTRB(12, 10, 12, 10),
        children: [
          Align(
            alignment: Alignment.centerLeft,
            child: Wrap(
              spacing: 10,
              runSpacing: 10,
              crossAxisAlignment: WrapCrossAlignment.center,
              children: children,
            ),
          ),
        ],
      ),
    );
  }

  Widget _field(String label, TextEditingController controller, {double width = 310, String? hint}) {
    return SizedBox(
      width: width,
      child: TextField(
        controller: controller,
        decoration: InputDecoration(
          labelText: label,
          hintText: hint,
          border: const OutlineInputBorder(),
          isDense: true,
        ),
      ),
    );
  }

  Widget _button(String label, Future<Object?> Function() action) {
    return FilledButton.tonal(
      onPressed: _busy ? null : () => _run(label, action),
      child: Text(label),
    );
  }

  Widget _note(String value) {
    return SizedBox(
      width: 620,
      child: Text(value, style: Theme.of(context).textTheme.bodySmall),
    );
  }

  Widget _generalSection() {
    return _section('General', [
      _field('Currency', _currency, width: 150),
      _field('Search term', _generalSearch),
      _button('Status', () async => general_api.getStatus()),
      _button('Currencies', () async => general_api.currencies()),
      _button('Overview', () async => general_api.overview(currency: _currency.text.trim())),
      _button('Search all', () async {
        return general_api.search(
          searchFilter: data.GeneralSearchFilterPayload(
            filter: data.GeneralSearchFilter(
              searchTerm: _generalSearch.text.trim(),
              currency: _currency.text.trim(),
              itemTypes: const [
                data.GeneralSearchFilterItemTypeFfi.company,
                data.GeneralSearchFilterItemTypeFfi.bill,
                data.GeneralSearchFilterItemTypeFfi.contact,
              ],
            ),
          ),
        );
      }),
    ], initiallyExpanded: true);
  }

  Widget _uploadSection() {
    return _section('Uploads / files', [
      _field('Local file path', _filePath, width: 620, hint: '/tmp/test.pdf'),
      _field('Upload ID', _fileUploadId, width: 420),
      _field('Stored file name', _fileName, width: 300),
      _button('Upload via identity', () => _upload(identity_api.upload)),
      _button('Upload via contact', () => _upload(contact_api.upload)),
      _button('Upload via company', () => _upload(company_api.upload)),
      _button('Upload via bill', () => _upload(bill_api.upload)),
      _button('Fetch temp file', () async {
        final file = await general_api.tempFile(fileUploadId: _required(_fileUploadId, 'Upload ID'));
        return _saveBinaryFile(file);
      }),
      _button('Attach identity profile pic', () async {
        await identity_api.change(
          identityPayload: _identityChange(
            profilePictureFileUploadId: data.EditOptionalFieldModeFfi.set_(
              _required(_fileUploadId, 'Upload ID'),
            ),
          ),
        );
        return 'OK';
      }),
      _button('Attach identity document', () async {
        await identity_api.change(
          identityPayload: _identityChange(
            identityDocumentFileUploadId: data.EditOptionalFieldModeFfi.set_(
              _required(_fileUploadId, 'Upload ID'),
            ),
          ),
        );
        return 'OK';
      }),
      _button('Attach contact avatar', () async {
        await contact_api.edit(
          contactPayload: _contactEdit(
            avatarFileUploadId: data.EditOptionalFieldModeFfi.set_(
              _required(_fileUploadId, 'Upload ID'),
            ),
          ),
        );
        return 'OK';
      }),
      _button('Remove contact avatar', () async {
        await contact_api.edit(
          contactPayload: _contactEdit(
            avatarFileUploadId: const data.EditOptionalFieldModeFfi.unset(),
          ),
        );
        return 'OK';
      }),
      _button('Attach company proof', () async {
        await company_api.edit(
          companyPayload: _companyEdit(
            proofOfRegistrationFileUploadId: data.EditOptionalFieldModeFfi.set_(
              _required(_fileUploadId, 'Upload ID'),
            ),
          ),
        );
        return 'OK';
      }),
      _button('Remove company proof', () async {
        await company_api.edit(
          companyPayload: _companyEdit(
            proofOfRegistrationFileUploadId: const data.EditOptionalFieldModeFfi.unset(),
          ),
        );
        return 'OK';
      }),
      _button('Fetch identity file', () async {
        final file = await identity_api.file(fileName: _required(_fileName, 'Stored file name'));
        return _saveBinaryFile(file);
      }),
      _button('Fetch contact file', () async {
        final file = await contact_api.file(
          nodeId: _required(_contactNodeId, 'Contact node ID'),
          fileName: _required(_fileName, 'Stored file name'),
        );
        return _saveBinaryFile(file);
      }),
      _button('Fetch company file', () async {
        final file = await company_api.file(
          id: _required(_companyId, 'Company ID'),
          fileName: _required(_fileName, 'Stored file name'),
        );
        return _saveBinaryFile(file);
      }),
      _button('Fetch bill attachment', () async {
        final file = await bill_api.attachment(
          billId: _required(_billId, 'Bill ID'),
          fileName: _required(_fileName, 'Stored file name'),
        );
        return _saveBinaryFile(file);
      }),
      _field('Blossom hash', _blossomHash, width: 420),
      _button('Build Blossom URL', () async {
        final hash = _required(_blossomHash, 'Blossom hash');
        return '$defaultBlossomServer/$hash';
      }),
      _note('Fetched binary files are written to ${widget.dataDirectory}/downloads.'),
    ]);
  }

  Widget _identitySection() {
    return _section('Identity', [
      _field('Name', _identityName),
      _field('Email', _identityEmail),
      _button('Create anon identity', () async {
        final result = await identity_api.create(
          identity: identity_data.NewIdentityPayload(
            t: BigInt.one,
            name: 'Cypherpunk',
            postalAddress: const data.CreateOptionalPostalAddressFfi(),
          ),
        );
        _identitySwitchNodeId.text = result.nodeId;
        return result;
      }),
      _button('Deanonymize anon identity', () async {
        final result = await identity_api.deanonymize(
          identity: identity_data.NewIdentityPayload(
            t: BigInt.zero,
            name: _required(_identityName, 'Identity name'),
            email: _emptyToNull(_identityEmail.text),
            postalAddress: const data.CreateOptionalPostalAddressFfi(
              country: 'AT',
              city: 'Vienna',
              zip: '1020',
              address: 'street 1',
            ),
          ),
        );
        _identitySwitchNodeId.text = result.nodeId;
        return result;
      }),
      _button('Detail', () async {
        final result = await identity_api.detail();
        _identitySwitchNodeId.text = result.nodeId;
        return result;
      }),
      _button('Active identity', () async => identity_api.active()),
      _button('Change name', () async {
        await identity_api.change(
          identityPayload: _identityChange(name: _required(_identityName, 'Identity name')),
        );
        return 'OK';
      }),
      _button('Change email', () async {
        await identity_api.changeEmail(
          identityEmailPayload: identity_data.ChangeIdentityEmailPayload(
            email: _required(_identityEmail, 'Identity email'),
          ),
        );
        return 'OK';
      }),
      _field('Switch identity', _identitySwitchNodeId, width: 480),
      _button('Switch identity', () async {
        await identity_api.switch_(
          payload: identity_data.SwitchIdentity(
            t: null,
            nodeId: _required(_identitySwitchNodeId, 'Switch node ID'),
          ),
        );
        return identity_api.active();
      }),
      _button('Seed backup', () async {
        final result = await identity_api.seedBackup();
        _seedPhrase.text = result.seedPhrase;
        return result;
      }),
      _field('Seed phrase', _seedPhrase, width: 620),
      _button('Seed recover', () async {
        await identity_api.seedRecover(
          seedPhrasePayload: identity_data.SeedPhrase(
            seedPhrase: _required(_seedPhrase, 'Seed phrase'),
          ),
        );
        return 'OK';
      }),
      _field('Email confirmation code', _identityConfirmationCode),
      _button('Confirm email', () async {
        await identity_api.confirmEmail(
          payload: identity_data.ConfirmEmailPayload(
            email: _required(_identityEmail, 'Identity email'),
          ),
        );
        return 'OK';
      }),
      _button('Verify email', () async {
        await identity_api.verifyEmail(
          payload: identity_data.VerifyEmailPayload(
            confirmationCode: _required(_identityConfirmationCode, 'Confirmation code'),
          ),
        );
        return 'OK';
      }),
      _button('Email confirmations', () async => identity_api.getEmailConfirmations()),
      _button('Sync identity chain', () async {
        await identity_api.syncIdentityChain();
        return 'OK';
      }),
      _button('Override identity from Nostr', () async {
        await identity_api.devModeOverrideIdentityChainFromNostr();
        return 'OK';
      }),
      _button('Full identity chain', () async => identity_api.devModeGetFullIdentityChain()),
    ]);
  }

  Widget _contactSection() {
    return _section('Contacts', [
      _field('Contact node ID', _contactNodeId, width: 480),
      _field('Contact name', _contactName),
      _field('Contact email', _contactEmail),
      _button('Create contact', () async {
        final result = await contact_api.create(contactPayload: _newContact(BigInt.zero));
        _contactNodeId.text = result.nodeId;
        return result;
      }),
      _button('Create anon contact', () async {
        final result = await contact_api.create(contactPayload: _newContact(BigInt.from(2)));
        _contactNodeId.text = result.nodeId;
        return result;
      }),
      _button('Deanonymize contact', () async {
        final result = await contact_api.deanonymize(contactPayload: _newContact(BigInt.zero));
        return result;
      }),
      _button('List', () async => contact_api.list()),
      _button('Detail', () async => contact_api.detail(nodeId: _required(_contactNodeId, 'Contact node ID'))),
      _button('Edit name/email', () async {
        await contact_api.edit(
          contactPayload: _contactEdit(
            name: _required(_contactName, 'Contact name'),
            email: _emptyToNull(_contactEmail.text),
          ),
        );
        return 'OK';
      }),
      _button('Delete', () async {
        await contact_api.remove(nodeId: _required(_contactNodeId, 'Contact node ID'));
        return 'OK';
      }),
      _field('Contact search', _contactSearch),
      _button('Search', () async {
        return contact_api.search(
          query: contact_data.SearchContactsPayload(
            searchTerm: _contactSearch.text.trim(),
            includeLogical: true,
            includeContact: true,
          ),
        );
      }),
    ]);
  }

  Widget _contactShareSection() {
    return _section('Contact sharing', [
      _field('Recipient node ID', _shareRecipientNodeId, width: 480),
      _button('Share current identity', () async {
        await identity_api.shareContactDetails(
          shareContactTo: identity_data.ShareContactTo(
            recipient: _required(_shareRecipientNodeId, 'Recipient node ID'),
          ),
        );
        return 'OK';
      }),
      _button('Share company', () async {
        await company_api.shareContactDetails(
          shareTo: identity_data.ShareCompanyContactTo(
            recipient: _required(_shareRecipientNodeId, 'Recipient node ID'),
            companyId: _required(_companyId, 'Company ID'),
          ),
        );
        return 'OK';
      }),
      _field('Pending receiver node ID', _pendingReceiverNodeId, width: 480),
      _button('List pending shares', () async {
        return contact_api.listPendingContactShares(
          receiverNodeId: _required(_pendingReceiverNodeId, 'Pending receiver node ID'),
        );
      }),
      _field('Pending share ID', _pendingShareId, width: 480),
      _button('Get pending share', () async {
        return contact_api.getPendingContactShare(id: _required(_pendingShareId, 'Pending share ID'));
      }),
      _button('Approve + add', () => _approveShare(add: true, shareBack: false)),
      _button('Approve + add + share back', () => _approveShare(add: true, shareBack: true)),
      _button('Approve + share back only', () => _approveShare(add: false, shareBack: true)),
      _button('Reject share', () async {
        await contact_api.rejectContactShare(
          pendingShareId: _required(_pendingShareId, 'Pending share ID'),
        );
        return 'OK';
      }),
    ]);
  }

  Widget _companySection() {
    return _section('Companies', [
      _field('Company ID', _companyId, width: 480),
      _field('Company name', _companyName),
      _field('Company email', _companyEmail),
      _button('Create New Company Id', () async {
        final result = await company_api.createKeys();
        _companyId.text = result.id;
        return result;
      }),
      _button('Create company', () async {
        final result = await company_api.create(
          companyPayload: company_data.CreateCompanyPayload(
            id: _required(_companyId, 'Company ID'),
            name: _required(_companyName, 'Company name'),
            postalAddress: const data.CreatePostalAddressFfi(
              country: 'AT',
              city: 'Vienna',
              zip: '1020',
              address: 'street 1',
            ),
            email: _required(_companyEmail, 'Company email'),
            creatorEmail: _required(_companyEmail, 'Company email'),
            proofOfRegistrationFileUploadId: _emptyToNull(_fileUploadId.text),
          ),
        );
        _companyId.text = result.id;
        return result;
      }),
      _button('Detail', () async => company_api.detail(id: _required(_companyId, 'Company ID'))),
      _button('List', () async => company_api.list()),
      _button('Update name/email', () async {
        await company_api.edit(
          companyPayload: _companyEdit(
            name: _required(_companyName, 'Company name'),
            email: _required(_companyEmail, 'Company email'),
          ),
        );
        return 'OK';
      }),
      _button('List signatories', () async => company_api.listSignatories(id: _required(_companyId, 'Company ID'))),
      _field('Signatory node ID', _companySignatoryNodeId, width: 480),
      _button('Invite signatory', () async {
        await company_api.inviteSignatory(
          companyPayload: company_data.InviteSignatoryPayload(
            id: _required(_companyId, 'Company ID'),
            signatoryNodeId: _required(_companySignatoryNodeId, 'Signatory node ID'),
          ),
        );
        return 'OK';
      }),
      _button('Remove signatory', () async {
        await company_api.removeSignatory(
          companyPayload: company_data.RemoveSignatoryPayload(
            id: _required(_companyId, 'Company ID'),
            signatoryNodeId: _required(_companySignatoryNodeId, 'Signatory node ID'),
          ),
        );
        return 'OK';
      }),
      _button('Hide signatory locally', () async {
        await company_api.locallyHideSignatory(
          payload: company_data.LocallyHideSignatoryPayload(
            id: _required(_companyId, 'Company ID'),
            signatoryNodeId: _required(_companySignatoryNodeId, 'Signatory node ID'),
          ),
        );
        return 'OK';
      }),
      _button('List invites', () async => company_api.listInvites()),
      _button('Accept invite', () async {
        await company_api.acceptInvite(
          payload: company_data.AcceptCompanyInvitePayload(
            id: _required(_companyId, 'Company ID'),
            email: _required(_companyEmail, 'Company email'),
          ),
        );
        return 'OK';
      }),
      _button('Reject invite', () async {
        await company_api.rejectInvite(companyId: _required(_companyId, 'Company ID'));
        return 'OK';
      }),
      _field('Signatory email', _companySignatoryEmail),
      _button('Change signatory email', () async {
        await company_api.changeSignatoryEmail(
          payload: company_data.ChangeSignatoryEmailPayload(
            id: _required(_companyId, 'Company ID'),
            email: _required(_companySignatoryEmail, 'Signatory email'),
          ),
        );
        return 'OK';
      }),
      _field('Company confirmation code', _companyConfirmationCode),
      _button('Confirm company email', () async {
        await company_api.confirmEmail(
          payload: company_data.CompanyConfirmEmailPayload(
            id: _required(_companyId, 'Company ID'),
            email: _required(_companyEmail, 'Company email'),
          ),
        );
        return 'OK';
      }),
      _button('Verify company email', () async {
        await company_api.verifyEmail(
          payload: company_data.CompanyVerifyEmailPayload(
            id: _required(_companyId, 'Company ID'),
            confirmationCode: _required(_companyConfirmationCode, 'Company confirmation code'),
          ),
        );
        return 'OK';
      }),
      _button('Company email confirmations', () async {
        return company_api.getEmailConfirmations(companyId: _required(_companyId, 'Company ID'));
      }),
      _button('Sync company chain', () async {
        await company_api.syncCompanyChain(
          payload: company_data.ResyncCompanyPayload(nodeId: _required(_companyId, 'Company ID')),
        );
        return 'OK';
      }),
      _button('Override company from Nostr', () async {
        await company_api.devModeOverrideCompanyChainFromNostr(
          payload: company_data.OverrideCompanyFromNostrPayload(
            nodeId: _required(_companyId, 'Company ID'),
          ),
        );
        return 'OK';
      }),
      _button('Full company chain', () async {
        return company_api.devModeGetFullCompanyChain(companyId: _required(_companyId, 'Company ID'));
      }),
    ]);
  }

  Widget _billCreationSection() {
    return _section('Bills - create / query', [
      _field('Bill ID', _billId, width: 520),
      _field('Counterparty contact node ID', _billCounterpartyNodeId, width: 520),
      _field('Bill sum', _billSum, width: 180),
      _button('Issue self-drafted', () => _issueBill(type: BigInt.one, blank: false)),
      _button('Issue promissory', () => _issueBill(type: BigInt.zero, blank: false)),
      _button('Issue blank promissory', () => _issueBill(type: BigInt.zero, blank: true)),
      _button('Detail', () async => bill_api.detail(id: _required(_billId, 'Bill ID'))),
      _button('List', () async => bill_api.list()),
      _button('List light', () async => bill_api.listLight()),
      _field('Bill search', _billSearch),
      _button('Search', () async {
        return bill_api.search(
          filterPayload: bill_data.BillsSearchFilterPayload(
            filter: bill_data.BillsSearchFilter(
              searchTerm: _emptyToNull(_billSearch.text),
              role: bill_data.BillsFilterRoleFfi.all,
              participants: const [],
              currency: _currency.text.trim(),
            ),
          ),
        );
      }),
      _button('Endorsements', () async => bill_api.endorsements(id: _required(_billId, 'Bill ID'))),
      _button('Past endorsees', () async => bill_api.pastEndorsees(id: _required(_billId, 'Bill ID'))),
      _button('Past payments', () async => bill_api.pastPayments(id: _required(_billId, 'Bill ID'))),
      _button('Bitcoin keys', () async => bill_api.bitcoinKeys(id: _required(_billId, 'Bill ID'))),
      _button('Bill history', () async => bill_api.billHistory(billId: _required(_billId, 'Bill ID'))),
      _button('Check this bill payment', () async {
        await bill_api.checkPaymentForBill(id: _required(_billId, 'Bill ID'));
        return 'OK';
      }),
      _button('Check all payments', () async {
        await bill_api.checkPayment();
        return 'OK';
      }),
      _button('Clear bill cache', () async {
        await bill_api.clearBillCache();
        return 'OK';
      })
    ]);
  }

  Widget _billActionSection() {
    return _section('Bills - actions', [
      _field('Endorsee / buyer / recoursee node ID', _billEndorseeNodeId, width: 520),
      _field('Action sum', _actionSum, width: 180),
      _field('Deadline days', _deadlineDays, width: 150),
      _button('Endorse', () async {
        await bill_api.endorseBill(
          endorseBillPayload: bill_data.EndorseBitcreditBillPayload(
            billId: _required(_billId, 'Bill ID'),
            endorsee: _required(_billEndorseeNodeId, 'Endorsee node ID'),
          ),
        );
        return 'OK';
      }),
      _button('Endorse blank', () async {
        await bill_api.endorseBillBlank(
          endorseBillPayload: bill_data.EndorseBitcreditBillPayload(
            billId: _required(_billId, 'Bill ID'),
            endorsee: _required(_billEndorseeNodeId, 'Endorsee node ID'),
          ),
        );
        return 'OK';
      }),
      _button('Request acceptance', () async {
        await bill_api.requestToAccept(
          requestToAcceptBillPayload: bill_data.RequestToAcceptBitcreditBillPayload(
            billId: _required(_billId, 'Bill ID'),
            acceptanceDeadline: _deadline(),
          ),
        );
        return 'OK';
      }),
      _button('Accept', () async {
        await bill_api.accept(
          acceptBillPayload: bill_data.AcceptBitcreditBillPayload(
            billId: _required(_billId, 'Bill ID'),
          ),
        );
        return 'OK';
      }),
      _button('Request payment', () async {
        await bill_api.requestToPay(
          requestToPayBillPayload: bill_data.RequestToPayBitcreditBillPayload(
            billId: _required(_billId, 'Bill ID'),
            currency: _currency.text.trim(),
            paymentDeadline: _deadline(),
          ),
        );
        return 'OK';
      }),
      _button('Offer to sell', () async {
        await bill_api.offerToSell(
          offerToSellPayload: bill_data.OfferToSellBitcreditBillPayload(
            buyer: _required(_billEndorseeNodeId, 'Buyer node ID'),
            billId: _required(_billId, 'Bill ID'),
            sum: _required(_actionSum, 'Action sum'),
            currency: _currency.text.trim(),
            buyingDeadline: _deadline(),
          ),
        );
        return 'OK';
      }),
      _button('Offer to sell blank', () async {
        await bill_api.offerToSellBlank(
          offerToSellPayload: bill_data.OfferToSellBitcreditBillPayload(
            buyer: _required(_billEndorseeNodeId, 'Buyer node ID'),
            billId: _required(_billId, 'Bill ID'),
            sum: _required(_actionSum, 'Action sum'),
            currency: _currency.text.trim(),
            buyingDeadline: _deadline(),
          ),
        );
        return 'OK';
      }),
      _button('Recourse for acceptance', () async {
        await bill_api.requestToRecourseBillAcceptance(
          requestRecoursePayload: bill_data.RequestRecourseForAcceptancePayload(
            billId: _required(_billId, 'Bill ID'),
            recoursee: _required(_billEndorseeNodeId, 'Recoursee node ID'),
            recourseDeadline: _deadline(),
          ),
        );
        return 'OK';
      }),
      _button('Recourse for payment', () async {
        await bill_api.requestToRecourseBillPayment(
          requestRecoursePayload: bill_data.RequestRecourseForPaymentPayload(
            billId: _required(_billId, 'Bill ID'),
            recoursee: _required(_billEndorseeNodeId, 'Recoursee node ID'),
            currency: _currency.text.trim(),
            sum: _required(_actionSum, 'Action sum'),
            recourseDeadline: _deadline(),
          ),
        );
        return 'OK';
      }),
      _button('Reject acceptance', () => _rejectBill(bill_api.rejectToAccept)),
      _button('Reject payment', () => _rejectBill(bill_api.rejectToPay)),
      _button('Reject buying', () => _rejectBill(bill_api.rejectToBuy)),
      _button('Reject recourse payment', () => _rejectBill(bill_api.rejectToPayRecourse)),
    ]);
  }

  Widget _billDevMintBtcSection() {
    return _section('Bills - dev / mint / Bitcoin', [
      _button('Sync bill chain', () async {
        await bill_api.syncBillChain(
          payload: bill_data.ResyncBillPayload(
            billId: _required(_billId, 'Bill ID'),
            fromNostr: false,
          ),
        );
        return 'OK';
      }),
      _button('Sync bill from Nostr', () async {
        await bill_api.syncBillChain(
          payload: bill_data.ResyncBillPayload(
            billId: _required(_billId, 'Bill ID'),
            fromNostr: true,
          ),
        );
        return 'OK';
      }),
      _button('Override bill from Nostr', () async {
        await bill_api.devModeOverrideBillChainFromNostr(
          payload: bill_data.OverrideBillFromNostrPayload(
            billId: _required(_billId, 'Bill ID'),
          ),
        );
        return 'OK';
      }),
      _button('Full bill chain', () async {
        return bill_api.devModeGetFullBillChain(billId: _required(_billId, 'Bill ID'));
      }),
      _field('Mint node ID', _mintNodeId, width: 620),
      _button('Request mint', () async {
        await bill_api.requestToMint(
          requestToMintBillPayload: bill_data.RequestToMintBitcreditBillPayload(
            mintNode: _required(_mintNodeId, 'Mint node ID'),
            billId: _required(_billId, 'Bill ID'),
          ),
        );
        return 'OK';
      }),
      _button('Mint state', () async {
        final result = await bill_api.mintState(id: _required(_billId, 'Bill ID'));
        if (result.requestStates.isNotEmpty) {
          _mintRequestId.text = result.requestStates.first.request.mintRequestId;
        }
        return result;
      }),
      _button('Check mint state', () async {
        await bill_api.checkMintState(id: _required(_billId, 'Bill ID'));
        return bill_api.mintState(id: _required(_billId, 'Bill ID'));
      }),
      _button('Reset local mint quote', () async {
        await bill_api.devModeResetBillMintQuoteState(
          payload: bill_data.BillResetMintQuoteState(billId: _required(_billId, 'Bill ID')),
        );
        return 'OK';
      }),
      _field('Mint request ID', _mintRequestId, width: 520),
      _button('Cancel mint request', () async {
        await bill_api.cancelRequestToMint(mintRequestId: _required(_mintRequestId, 'Mint request ID'));
        return 'OK';
      }),
      _button('Accept mint offer', () async {
        await bill_api.acceptMintOffer(mintRequestId: _required(_mintRequestId, 'Mint request ID'));
        return 'OK';
      }),
      _button('Reject mint offer', () async {
        await bill_api.rejectMintOffer(mintRequestId: _required(_mintRequestId, 'Mint request ID'));
        return 'OK';
      }),
      _field('Mint payment BTC address', _mintPaymentAddress, width: 520),
      _button('Request payment as mint', () async {
        await bill_api.requestToPayAsMint(
          requestToPayBillPayload: bill_data.RequestToPayAsMintBitcreditBillPayload(
            billId: _required(_billId, 'Bill ID'),
            currency: _currency.text.trim(),
            paymentDeadline: _deadline(),
            paymentAddress: _required(_mintPaymentAddress, 'Mint payment BTC address'),
          ),
        );
        return 'OK';
      }),
      _field('Court node ID', _courtNodeId, width: 520),
      _button('Share bill with court', () async {
        await bill_api.shareBillWithCourt(
          payload: bill_data.ShareBillWithCourtPayload(
            billId: _required(_billId, 'Bill ID'),
            courtNodeId: _required(_courtNodeId, 'Court node ID'),
          ),
        );
        return 'OK';
      }),
      _field('BTC address', _btcAddress, width: 520),
      _button('Mempool link', () async {
        return general_api.mempoolLink(
          pl: data.BtcAddressPayload(address: _required(_btcAddress, 'BTC address')),
        );
      }),
      _button('Link to pay', () async {
        return general_api.linkToPay(
          pl: data.BtcAddressAndSumPayload(
            billId: _required(_billId, 'Bill ID'),
            address: _required(_btcAddress, 'BTC address'),
            sum: _required(_actionSum, 'Action sum'),
          ),
        );
      }),
      _field('Sweep source address', _btcSourceAddress, width: 520),
      _field('Sweep destination address', _btcDestinationAddress, width: 520),
      _field('Sweep fee (sat)', _btcFee, width: 180),
      _button('Estimate sweep', () async {
        return bill_api.checkAndEstimateBtcSweep(
          payload: bill_data.BillCheckSweepBTCFundsPayload(
            billId: _required(_billId, 'Bill ID'),
            sourceAddress: _required(_btcSourceAddress, 'Sweep source address'),
            destinationAddress: _required(_btcDestinationAddress, 'Sweep destination address'),
          ),
        );
      }),
      _button('Sweep BTC funds', () async {
        return bill_api.sweepBtcFunds(
          payload: bill_data.BillSweepBTCFundsPayload(
            billId: _required(_billId, 'Bill ID'),
            sourceAddress: _required(_btcSourceAddress, 'Sweep source address'),
            destinationAddress: _required(_btcDestinationAddress, 'Sweep destination address'),
            fee: BigInt.parse(_required(_btcFee, 'Sweep fee')),
          ),
        );
      }),
    ]);
  }

  Widget _notificationSection() {
    return _section('Notifications', [
      _field('Node IDs (comma/newline separated)', _notificationNodeIds, width: 620),
      _button('Active status', () async {
        return notification_api.activeNotificationsForNodeIds(nodeIds: _nodeIds());
      }),
      _button('List notifications', () async {
        return notification_api.list(
          filters: data.NotificationFiltersFfi(nodeIds: _nodeIds().isEmpty ? null : _nodeIds()),
        );
      }),
      _button('Subscribe', () async {
        if (_notificationSubscribed) return 'Already subscribed';
        _notificationSubscribed = true;
        await notification_api.subscribe(
          callback: (event) {
            if (!mounted) return;
            setState(() {
              _console.add('[notification] ${event.value}');
            });
          },
        );
        return 'Subscription registered';
      }),
      _field('Notification ID', _notificationId, width: 480),
      _button('Mark as done', () async {
        await notification_api.markAsDone(notificationId: _required(_notificationId, 'Notification ID'));
        return 'OK';
      }),
      _button('Email preferences link', () async => notification_api.getEmailNotificationsPreferencesLink()),
      _note('The old browser harness had a local push "trigger test message" helper. The current Flutter notification API exposes status/list/subscribe/mark-done/preferences, but no equivalent trigger helper.'),
    ]);
  }

  Widget _resendQueueSection() {
    return _section('Resend queue', [
      _button('Fetch resend queue', () async => general_api.fetchResendQueueEntries()),
      _field('Failed resend queue entry ID', _resendQueueId, width: 520),
      _button('Requeue failed entry', () async {
        await general_api.requeueFailedResendQueueEntry(
          pl: data.RequeueFailedResendMessagePayload(id: _required(_resendQueueId, 'Resend queue ID')),
        );
        return 'OK';
      }),
    ]);
  }

  Future<void> _run(String label, Future<Object?> Function() action) async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _console.add('> $label');
    });
    final stopwatch = Stopwatch()..start();
    try {
      final result = await action();
      stopwatch.stop();
      if (!mounted) return;
      setState(() {
        _console.add('OK $label (${stopwatch.elapsedMilliseconds} ms)\n${mappings.pretty(result)}');
      });
    } catch (error, stackTrace) {
      stopwatch.stop();
      if (!mounted) return;
      setState(() {
        _console.add(
          'ERROR $label (${stopwatch.elapsedMilliseconds} ms)\n$error\n\n$stackTrace',
        );
      });
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<Object?> _upload(
    Future<data.UploadFileResponse> Function({required data.UploadFile uploadFile}) upload,
  ) async {
    final path = _required(_filePath, 'Local file path');
    final file = File(path);
    if (!await file.exists()) throw StateError('File does not exist: $path');
    final bytes = await file.readAsBytes();
    final name = file.uri.pathSegments.isEmpty ? 'upload.bin' : file.uri.pathSegments.last;
    final dot = name.lastIndexOf('.');
    final extension = dot >= 0 && dot < name.length - 1 ? name.substring(dot + 1) : null;
    final result = await upload(
      uploadFile: data.UploadFile(data: bytes, extension_: extension, name: name),
    );
    _fileUploadId.text = result.fileUploadId;
    _fileName.text = name;
    return result;
  }

  Future<Object?> _saveBinaryFile(data.BinaryFileResponse file) async {
    final dir = Directory('${widget.dataDirectory}/downloads');
    await dir.create(recursive: true);
    final safeName = file.name.replaceAll(RegExp(r'[/\\]'), '_');
    final target = File('${dir.path}/$safeName');
    await target.writeAsBytes(file.data, flush: true);
    return {
      'savedTo': target.path,
      'name': file.name,
      'contentType': file.contentType,
      'bytes': file.data.length,
    };
  }

  identity_data.ChangeIdentityPayload _identityChange({
    String? name,
    data.EditOptionalFieldModeFfi? profilePictureFileUploadId,
    data.EditOptionalFieldModeFfi? identityDocumentFileUploadId,
  }) {
    return identity_data.ChangeIdentityPayload(
      name: name,
      postalAddressZip: const data.EditOptionalFieldModeFfi.ignore(),
      dateOfBirth: const data.EditOptionalFieldModeFfi.ignore(),
      countryOfBirth: const data.EditOptionalFieldModeFfi.ignore(),
      cityOfBirth: const data.EditOptionalFieldModeFfi.ignore(),
      identificationNumber: const data.EditOptionalFieldModeFfi.ignore(),
      profilePictureFileUploadId:
          profilePictureFileUploadId ?? const data.EditOptionalFieldModeFfi.ignore(),
      identityDocumentFileUploadId:
          identityDocumentFileUploadId ?? const data.EditOptionalFieldModeFfi.ignore(),
    );
  }

  contact_data.EditContactPayload _contactEdit({
    String? name,
    String? email,
    data.EditOptionalFieldModeFfi? avatarFileUploadId,
  }) {
    return contact_data.EditContactPayload(
      nodeId: _required(_contactNodeId, 'Contact node ID'),
      name: name,
      email: email,
      postalAddressZip: const data.EditOptionalFieldModeFfi.ignore(),
      dateOfBirthOrRegistration: const data.EditOptionalFieldModeFfi.ignore(),
      countryOfBirthOrRegistration: const data.EditOptionalFieldModeFfi.ignore(),
      cityOfBirthOrRegistration: const data.EditOptionalFieldModeFfi.ignore(),
      identificationNumber: const data.EditOptionalFieldModeFfi.ignore(),
      avatarFileUploadId: avatarFileUploadId ?? const data.EditOptionalFieldModeFfi.ignore(),
      proofDocumentFileUploadId: const data.EditOptionalFieldModeFfi.ignore(),
    );
  }

  company_data.EditCompanyPayload _companyEdit({
    String? name,
    String? email,
    data.EditOptionalFieldModeFfi? proofOfRegistrationFileUploadId,
  }) {
    return company_data.EditCompanyPayload(
      id: _required(_companyId, 'Company ID'),
      name: name,
      email: email,
      postalAddressZip: const data.EditOptionalFieldModeFfi.ignore(),
      countryOfRegistration: const data.EditOptionalFieldModeFfi.ignore(),
      cityOfRegistration: const data.EditOptionalFieldModeFfi.ignore(),
      registrationNumber: const data.EditOptionalFieldModeFfi.ignore(),
      registrationDate: const data.EditOptionalFieldModeFfi.ignore(),
      logoFileUploadId: const data.EditOptionalFieldModeFfi.ignore(),
      proofOfRegistrationFileUploadId:
          proofOfRegistrationFileUploadId ?? const data.EditOptionalFieldModeFfi.ignore(),
    );
  }

  contact_data.NewContactPayload _newContact(BigInt type) {
    return contact_data.NewContactPayload(
      t: type,
      nodeId: _required(_contactNodeId, 'Contact node ID'),
      name: _required(_contactName, 'Contact name'),
      email: _emptyToNull(_contactEmail.text),
      postalAddress: const data.CreatePostalAddressFfi(
        country: 'AT',
        city: 'Vienna',
        zip: '1020',
        address: 'street 1',
      ),
      avatarFileUploadId: _emptyToNull(_fileUploadId.text),
    );
  }

  Future<Object?> _approveShare({required bool add, required bool shareBack}) async {
    await contact_api.approveContactShare(
      approvePayload: contact_data.ApproveContactSharePayload(
        pendingShareId: _required(_pendingShareId, 'Pending share ID'),
        addToContacts: add,
        shareBack: shareBack,
      ),
    );
    return 'OK';
  }

  Future<Object?> _issueBill({required BigInt type, required bool blank}) async {
    final identity = await identity_api.detail();
    final counterparty = _required(_billCounterpartyNodeId, 'Counterparty contact node ID');
    final issueDate = _date(DateTime.now());
    final maturityDate = _date(DateTime.now().add(const Duration(days: 1)));
    // final maturityDate = issueDate;
    final payload = bill_data.BitcreditBillPayload(
      t: type,
      countryOfIssuing: 'at',
      cityOfIssuing: 'Vienna',
      issueDate: issueDate,
      maturityDate: maturityDate,
      payee: type == BigInt.zero ? counterparty : identity.nodeId,
      drawee: type == BigInt.zero ? identity.nodeId : counterparty,
      sum: _required(_billSum, 'Bill sum'),
      currency: _required(_currency, 'Currency'),
      countryOfPayment: 'GB',
      cityOfPayment: 'London',
      fileUploadIds: _fileUploadId.text.trim().isEmpty ? const [] : [_fileUploadId.text.trim()],
    );
    final result = blank
        ? await bill_api.issueBlank(billPayload: payload)
        : await bill_api.issue(billPayload: payload);
    _billId.text = result.id;
    return result;
  }

  Future<Object?> _rejectBill(
    Future<void> Function({required bill_data.RejectActionBillPayload rejectPayload}) reject,
  ) async {
    await reject(
      rejectPayload: bill_data.RejectActionBillPayload(billId: _required(_billId, 'Bill ID')),
    );
    return 'OK';
  }

  String _deadline() {
    final days = int.tryParse(_deadlineDays.text.trim()) ?? 7;
    return _date(DateTime.now().add(Duration(days: days)));
  }

  List<String> _nodeIds() {
    return _notificationNodeIds.text
        .split(RegExp(r'[,\n\s]+'))
        .map((value) => value.trim())
        .where((value) => value.isNotEmpty)
        .toList();
  }

  String _required(TextEditingController controller, String label) {
    final value = controller.text.trim();
    if (value.isEmpty) throw ArgumentError('$label is required');
    return value;
  }

  String? _emptyToNull(String value) {
    final trimmed = value.trim();
    return trimmed.isEmpty ? null : trimmed;
  }

  String _date(DateTime value) {
    String two(int n) => n.toString().padLeft(2, '0');
    return '${value.year}-${two(value.month)}-${two(value.day)}';
  }


  Future<void> _resetState() async {
    await DevEnvironment.requestReset(widget.dataDirectory);

    if (Platform.isLinux || Platform.isMacOS || Platform.isWindows) {
      exit(0);
    }

    if (!mounted) {
      return;
    }

    ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text(
            'Reset scheduled. Fully close and restart the app.',
            ),
          ),
        );
  }
}

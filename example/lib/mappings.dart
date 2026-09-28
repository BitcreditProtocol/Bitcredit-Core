import 'dart:convert';

import 'package:ebill_flutter_ffi/data/bill.dart' as bill_data;
import 'package:ebill_flutter_ffi/data/company.dart' as company_data;
import 'package:ebill_flutter_ffi/data/contact.dart' as contact_data;
import 'package:ebill_flutter_ffi/data/identity.dart' as identity_data;
import 'package:ebill_flutter_ffi/data/lib.dart' as data;
import 'package:ebill_flutter_ffi/data/mint.dart' as mint_data;
import 'package:ebill_flutter_ffi/data/notification.dart' as notification_data;


String pretty(Object? value) {
  try {
    return const JsonEncoder.withIndent('  ').convert(_simplify(value));
  } catch (_) {
    return '$value';
  }
}

// custom expansion for some types and defaults for others
// if this becomes unwieldy, we can use JSON serialization by making all
// rust ffi types Serialize/Deserialize and adding a to_json helper
Object? _simplify(Object? value) {
  if (value == null || value is num || value is bool) return value;

  if (value is String) {
      final trimmed = value.trim();
      // Some FFI APIs return JSON objects/arrays encoded as strings
      if ((trimmed.startsWith('{') && trimmed.endsWith('}')) ||
              (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
          try {
              final decoded = jsonDecode(trimmed);
              return _simplify(decoded);
          } catch (_) {
              // Not valid JSON; leave it as a normal string
          }
      }

      return value;
  }

  if (value is BigInt) return value.toString();
  if (value is Enum) return value.name;
  if (value is Iterable) return value.map(_simplify).toList();
  if (value is Map) return value.map((key, item) => MapEntry('$key', _simplify(item)));

  if (value is data.StatusResponse) {
    return {
      'bitcoinNetwork': value.bitcoinNetwork,
      'connected': value.connected,
      'appVersion': value.appVersion,
    };
  }
  if (value is data.CurrenciesResponse) {
    return {'currencies': value.currencies.map((item) => item.code).toList()};
  }
  if (value is data.OverviewResponse) {
    return {
      'currency': value.currency,
      'balances': {
        'payee': value.balances.payee.sum,
        'payer': value.balances.payer.sum,
        'contingent': value.balances.contingent.sum,
      },
    };
  }
  if (value is data.UploadFileResponse) return {'fileUploadId': value.fileUploadId};
  if (value is data.BinaryFileResponse) {
    return {'name': value.name, 'contentType': value.contentType, 'bytes': value.data.length};
  }
  if (value is data.LinkToPayResponse) return {'linkToPay': value.linkToPay};
  if (value is data.MempoolLinkResponse) return {'mempoolLink': value.mempoolLink};
  if (value is data.GeneralSearchResponse) {
    return {
      'bills': value.bills.map(_simplify).toList(),
      'contacts': value.contacts.map(_simplify).toList(),
      'companies': value.companies.map(_simplify).toList(),
    };
  }
  if (value is data.ResendQueueEntry) {
    return {
      'id': value.id,
      'senderId': value.senderId,
      'eventType': value.eventType,
      'status': '${value.status}',
      'recipient': value.recipient,
      'blockHeight': value.blockHeight?.toString(),
      'blockOpCode': value.blockOpCode,
    };
  }

  if (value is identity_data.IdentityFfi) {
    return {
      'type': '${value.t}',
      'nodeId': value.nodeId,
      'name': value.name,
      'email': value.email,
      'npub': value.npub,
      'bitcoinPublicKey': value.bitcoinPublicKey,
      'postalAddress': _postal(value.postalAddress),
      'profilePicture': value.profilePictureFile?.name,
      'identityDocument': value.identityDocumentFile?.name,
      'nostrRelays': value.nostrRelays,
    };
  }
  if (value is identity_data.SwitchIdentity) {
    return {'type': '${value.t}', 'nodeId': value.nodeId};
  }
  if (value is identity_data.SeedPhrase) return {'seedPhrase': value.seedPhrase};
  if (value is identity_data.IdentityEmailConfirmationFfi) {
    return {
      'nodeId': value.nodeId,
      'companyNodeId': value.companyNodeId,
      'email': value.email,
      'createdAt': value.createdAt.toString(),
      'witness': value.witness,
      'signature': value.signature,
    };
  }

  if (value is contact_data.ContactFfi) {
    return {
      'type': '${value.t}',
      'nodeId': value.nodeId,
      'name': value.name,
      'email': value.email,
      'postalAddress': value.postalAddress == null ? null : _postal(value.postalAddress!),
      'avatar': value.avatarFile?.name,
      'proofDocument': value.proofDocumentFile?.name,
      'isLogical': value.isLogical,
      'nostrRelays': value.nostrRelays,
    };
  }
  if (value is contact_data.ContactsResponse) return value.contacts.map(_simplify).toList();
  if (value is contact_data.PendingContactSharesResponse) {
    return value.pendingShares.map(_simplify).toList();
  }
  if (value is contact_data.PendingContactShareFfi) {
    return {
      'id': value.id,
      'nodeId': value.nodeId,
      'senderNodeId': value.senderNodeId,
      'receiverNodeId': value.receiverNodeId,
      'receivedAt': value.receivedAt.toString(),
      'contact': _simplify(value.contact),
    };
  }

  if (value is company_data.CompanyKeysFfi) return {'id': value.id};
  if (value is company_data.CompanyFfi) {
    return {
      'id': value.id,
      'name': value.name,
      'email': value.email,
      'status': '${value.status}',
      'postalAddress': _postal(value.postalAddress),
      'countryOfRegistration': value.countryOfRegistration,
      'cityOfRegistration': value.cityOfRegistration,
      'registrationNumber': value.registrationNumber,
      'registrationDate': value.registrationDate,
      'proof': value.proofOfRegistrationFile?.name,
      'logo': value.logoFile?.name,
      'signatories': value.signatories
          .map((item) => {'nodeId': item.nodeId, 'status': '${item.status}'})
          .toList(),
    };
  }
  if (value is company_data.CompaniesResponse) return value.companies.map(_simplify).toList();
  if (value is company_data.ListSignatoriesResponse) {
    return value.signatories
        .map((item) => {
              'type': '${item.t}',
              'nodeId': item.nodeId,
              'name': item.name,
              'isLogical': item.isLogical,
              'status': '${item.signatory.status}',
            })
        .toList();
  }

  if (value is bill_data.BillIdResponse) {
    return {
      'id': value.id,
    };
  }
  if (value is bill_data.BitcreditBillFfi) {
    return {
      'id': value.id,
      'participants': _simplify(value.participants),
      'data': _simplify(value.data),
      'status': _simplify(value.status),
      'state': _simplify(value.state),
      'currentWaitingState': _simplify(value.currentWaitingState),
      'actions': _simplify(value.actions),
    };
  }

  if (value is bill_data.BillsResponse) {
    return value.bills.map(_simplify).toList();
  }
  if (value is bill_data.BillStateFfi) {
    return {
      'mint': _simplify(value.mint),
      'accept': _simplify(value.accept),
      'payment': _simplify(value.payment),
    };
  }

  if (value is bill_data.BillAcceptStateFfi) {
    return value.when<Object?>(
      none: () => {
        'type': 'none',
      },
      requested: (timestamp) => {
        'type': 'requested',
        'timestamp': _simplify(timestamp),
      },
      accepted: (timestamp) => {
        'type': 'accepted',
        'timestamp': _simplify(timestamp),
      },
      expired: (timestamp) => {
        'type': 'expired',
        'timestamp': _simplify(timestamp),
      },
      rejected: (timestamp) => {
        'type': 'rejected',
        'timestamp': _simplify(timestamp),
      },
    );
  }

  if (value is bill_data.BillPaymentStateFfi) {
    return value.when<Object?>(
      none: () => {
        'type': 'none',
      },
      requested: (timestamp) => {
        'type': 'requested',
        'timestamp': _simplify(timestamp),
      },
      paid: (timestamp) => {
        'type': 'paid',
        'timestamp': _simplify(timestamp),
      },
      expired: (timestamp) => {
        'type': 'expired',
        'timestamp': _simplify(timestamp),
      },
      rejected: (timestamp) => {
        'type': 'rejected',
        'timestamp': _simplify(timestamp),
      },
    );
  }

  if (value is bill_data.BillStatusFfi) {
    return {
      'acceptance': _simplify(value.acceptance),
      'payment': _simplify(value.payment),
      'sell': _simplify(value.sell),
      'recourse': _simplify(value.recourse),
      'mint': _simplify(value.mint),
      'redeemedFundsAvailable': value.redeemedFundsAvailable,
      'hasRequestedFunds': value.hasRequestedFunds,
      'lastBlockTime': _simplify(value.lastBlockTime),
    };
  }

  if (value is bill_data.BillAcceptanceStatusFfi) {
    return {
      'timeOfRequestToAccept': _simplify(value.timeOfRequestToAccept),
      'requestedToAccept': value.requestedToAccept,
      'accepted': value.accepted,
      'requestToAcceptTimedOut': value.requestToAcceptTimedOut,
      'rejectedToAccept': value.rejectedToAccept,
      'acceptanceDeadlineTimestamp':
          _simplify(value.acceptanceDeadlineTimestamp),
    };
  }

  if (value is bill_data.BillPaymentStatusFfi) {
    return {
      'timeOfRequestToPay': _simplify(value.timeOfRequestToPay),
      'requestedToPay': value.requestedToPay,
      'paid': value.paid,
      'requestToPayTimedOut': value.requestToPayTimedOut,
      'rejectedToPay': value.rejectedToPay,
      'paymentDeadlineTimestamp':
          _simplify(value.paymentDeadlineTimestamp),
    };
  }

  if (value is bill_data.BillSellStatusFfi) {
    return {
      'timeOfLastOfferToSell': _simplify(value.timeOfLastOfferToSell),
      'sold': value.sold,
      'offeredToSell': value.offeredToSell,
      'offerToSellTimedOut': value.offerToSellTimedOut,
      'rejectedOfferToSell': value.rejectedOfferToSell,
      'buyingDeadlineTimestamp':
          _simplify(value.buyingDeadlineTimestamp),
    };
  }

  if (value is bill_data.BillRecourseStatusFfi) {
    return {
      'timeOfLastRequestToRecourse':
          _simplify(value.timeOfLastRequestToRecourse),
      'recoursed': value.recoursed,
      'requestedToRecourse': value.requestedToRecourse,
      'requestToRecourseTimedOut':
          value.requestToRecourseTimedOut,
      'rejectedRequestToRecourse':
          value.rejectedRequestToRecourse,
      'recourseDeadlineTimestamp':
          _simplify(value.recourseDeadlineTimestamp),
    };
  }

  if (value is bill_data.BillMintStatusFfi) {
    return {
      'hasMintRequests': value.hasMintRequests,
    };
  }
  if (value is bill_data.BillDataFfi) {
    return {
      'timeOfDrawing': _simplify(value.timeOfDrawing),
      'issueDate': value.issueDate,
      'timeOfMaturity': _simplify(value.timeOfMaturity),
      'maturityDate': value.maturityDate,
      'countryOfIssuing': value.countryOfIssuing,
      'cityOfIssuing': value.cityOfIssuing,
      'countryOfPayment': value.countryOfPayment,
      'cityOfPayment': value.cityOfPayment,
      'currency': value.currency,
      'sum': value.sum,
      'files': _simplify(value.files),
      'activeNotification': _simplify(value.activeNotification),
    };
  }
  if (value is data.FileFfi) {
    return {
      'name': value.name,
      'hash': value.hash,
      'nostrHash': value.nostrHash,
    };
  }
  if (value is bill_data.BillParticipantsFfi) {
    return {
      'drawee': _simplify(value.drawee),
      'drawer': _simplify(value.drawer),
      'payee': _simplify(value.payee),
      'endorsee': _simplify(value.endorsee),
      'endorsementsCount': _simplify(value.endorsementsCount),
      'allParticipantNodeIds':
          _simplify(value.allParticipantNodeIds),
    };
  }

  if (value is bill_data.BillParticipantFfi) {
    return value.when<Object?>(
      anon: (participant) => {
        'type': 'anon',
        'participant': _simplify(participant),
      },
      ident: (participant) => {
        'type': 'ident',
        'participant': _simplify(participant),
      },
    );
  }

  if (value is bill_data.BillAnonParticipantFfi) {
    return {
      'nodeId': value.nodeId,
      'nostrRelays': value.nostrRelays,
    };
  }

  if (value is bill_data.BillIdentParticipantFfi) {
    return {
      'type': _simplify(value.t),
      'nodeId': value.nodeId,
      'name': value.name,
      'postalAddress': _postal(value.postalAddress),
      'email': value.email,
      'nostrRelays': value.nostrRelays,
    };
  }
  if (value is bill_data.BillCallerActionsFfi) {
    return {
      'billActions': _simplify(value.billActions),
      'paymentActions': _simplify(value.paymentActions),
    };
  }

  if (value is bill_data.BillCallerPaymentActionFfi) {
    return value.when<Object?>(
      pay: (payment) => {
        'type': 'pay',
        'payment': _simplify(payment),
      },
      checkPayment: (payment) => {
        'type': 'checkPayment',
        'payment': _simplify(payment),
      },
    );
  }

  if (value is bill_data.BillCallerPaymentFfi) {
    return value.when<Object?>(
      sell: (buyer, seller, state) => {
        'type': 'sell',
        'buyer': _simplify(buyer),
        'seller': _simplify(seller),
        'state': _simplify(state),
      },
      payment: (payer, payee, state) => {
        'type': 'payment',
        'payer': _simplify(payer),
        'payee': _simplify(payee),
        'state': _simplify(state),
      },
      recourse: (recourser, recoursee, state) => {
        'type': 'recourse',
        'recourser': _simplify(recourser),
        'recoursee': _simplify(recoursee),
        'state': _simplify(state),
      },
    );
  }

  if (value is bill_data.BillCallerPaymentStateFfi) {
    return {
      'timeOfRequest': _simplify(value.timeOfRequest),
      'currency': value.currency,
      'sum': value.sum,
      'addressToPay': value.addressToPay,
      'status': _simplify(value.status),
      'paymentDeadline': _simplify(value.paymentDeadline),
      'txId': value.txId,
      'inMempool': value.inMempool,
      'confirmations': _simplify(value.confirmations),
      'privateDescriptorToSpend':
          value.privateDescriptorToSpend,
    };
  }
  if (value is bill_data.PaymentStatusFfi) {
    return value.when<Object?>(
      requested: (timestamp) => {
        'type': 'requested',
        'timestamp': _simplify(timestamp),
      },
      paid: (timestamp) => {
        'type': 'paid',
        'timestamp': _simplify(timestamp),
      },
      rejected: (timestamp) => {
        'type': 'rejected',
        'timestamp': _simplify(timestamp),
      },
      expired: (timestamp) => {
        'type': 'expired',
        'timestamp': _simplify(timestamp),
      },
    );
  }

  if (value is bill_data.BillCurrentWaitingStateFfi) {
    return value.when<Object?>(
      sell: (state) => {
        'type': 'sell',
        'state': _simplify(state),
      },
      payment: (state) => {
        'type': 'payment',
        'state': _simplify(state),
      },
      recourse: (state) => {
        'type': 'recourse',
        'state': _simplify(state),
      },
    );
  }

  if (value is bill_data.BillWaitingStatePaymentDataFfi) {
    return {
      'timeOfRequest': _simplify(value.timeOfRequest),
      'currency': value.currency,
      'sum': value.sum,
      'addressToPay': value.addressToPay,
      'txId': value.txId,
      'inMempool': value.inMempool,
      'confirmations': _simplify(value.confirmations),
      'paymentDeadline': _simplify(value.paymentDeadline),
    };
  }

  if (value is bill_data.BillWaitingForSellStateFfi) {
    return {
      'buyer': _simplify(value.buyer),
      'seller': _simplify(value.seller),
      'paymentData': _simplify(value.paymentData),
    };
  }

  if (value is bill_data.BillWaitingForPaymentStateFfi) {
    return {
      'payer': _simplify(value.payer),
      'payee': _simplify(value.payee),
      'paymentData': _simplify(value.paymentData),
    };
  }

  if (value is bill_data.BillWaitingForRecourseStateFfi) {
    return {
      'recourser': _simplify(value.recourser),
      'recoursee': _simplify(value.recoursee),
      'paymentData': _simplify(value.paymentData),
    };
  }

  if (value is bill_data.LightBitcreditBillFfi) {
    return {
      'id': value.id,
      'drawee': _simplify(value.drawee),
      'drawer': _simplify(value.drawer),
      'payee': _simplify(value.payee),
      'endorsee': _simplify(value.endorsee),
      'activeNotification':
          _simplify(value.activeNotification),
      'sum': value.sum,
      'currency': value.currency,
      'issueDate': value.issueDate,
      'timeOfDrawing': _simplify(value.timeOfDrawing),
      'timeOfMaturity': _simplify(value.timeOfMaturity),
      'lastBlockTime': _simplify(value.lastBlockTime),
    };
  }

  if (value is bill_data.LightBillsResponse) {
    return value.bills.map(_simplify).toList();
  }

  if (value is bill_data.LightBillParticipantFfi) {
    return value.when<Object?>(
      anon: (participant) => {
        'type': 'anon',
        'participant': _simplify(participant),
      },
      ident: (participant) => {
        'type': 'ident',
        'participant': _simplify(participant),
      },
    );
  }

  if (value is bill_data.LightBillAnonParticipantFfi) {
    return {
      'nodeId': value.nodeId,
    };
  }

  if (value is bill_data.LightBillIdentParticipantFfi) {
    return {
      'type': _simplify(value.t),
      'name': value.name,
      'nodeId': value.nodeId,
    };
  }

  if (value is bill_data.LightBillIdentParticipantWithAddressFfi) {
    return {
      'type': _simplify(value.t),
      'name': value.name,
      'nodeId': value.nodeId,
      'postalAddress': _postal(value.postalAddress),
    };
  }

  if (value is bill_data.LightBillSignatoryFfi) {
    return {
      'name': value.name,
      'nodeId': value.nodeId,
    };
  }

  if (value is bill_data.LightSignedByFfi) {
    return {
      'data': _simplify(value.data),
      'signatory': _simplify(value.signatory),
    };
  }

  if (value is bill_data.BillHistoryResponse) {
    return {
      'blocks': value.blocks.map(_simplify).toList(),
    };
  }

  if (value is bill_data.BillHistoryBlockFfi) {
    return {
      'blockId': _simplify(value.blockId),
      'blockType': _simplify(value.blockType),
      'payToTheOrderOf':
          _simplify(value.payToTheOrderOf),
      'paymentData': _simplify(value.paymentData),
      'requestDeadline':
          _simplify(value.requestDeadline),
      'signed': _simplify(value.signed),
      'signingTimestamp':
          _simplify(value.signingTimestamp),
      'signingAddress': value.signingAddress == null
          ? null
          : _postal(value.signingAddress!),
    };
  }

  if (value is bill_data.BillHistoryBlockPaymentDataFfi) {
    return {
      'currency': value.currency,
      'sum': value.sum,
      'paymentAddress': value.paymentAddress,
    };
  }
  if (value is bill_data.EndorsementsResponse) {
    return {
      'endorsements':
          value.endorsements.map(_simplify).toList(),
    };
  }

  if (value is bill_data.EndorsementFfi) {
    return {
      'payToTheOrderOf':
          _simplify(value.payToTheOrderOf),
      'signed': _simplify(value.signed),
      'signingTimestamp':
          _simplify(value.signingTimestamp),
      'signingAddress': value.signingAddress == null
          ? null
          : _postal(value.signingAddress!),
    };
  }

  if (value is bill_data.PastEndorseesResponse) {
    return {
      'pastEndorsees':
          value.pastEndorsees.map(_simplify).toList(),
    };
  }

  if (value is bill_data.PastEndorseeFfi) {
    return {
      'payToTheOrderOf':
          _simplify(value.payToTheOrderOf),
      'signed': _simplify(value.signed),
      'signingTimestamp':
          _simplify(value.signingTimestamp),
      'signingAddress': value.signingAddress == null
          ? null
          : _postal(value.signingAddress!),
    };
  }

  if (value is bill_data.PastPaymentsResponse) {
    return {
      'pastPayments':
          value.pastPayments.map(_simplify).toList(),
    };
  }

  if (value is bill_data.PastPaymentResultFfi) {
    return value.when<Object?>(
      sell: (payment) => {
        'type': 'sell',
        'data': _simplify(payment),
      },
      payment: (payment) => {
        'type': 'payment',
        'data': _simplify(payment),
      },
      recourse: (payment) => {
        'type': 'recourse',
        'data': _simplify(payment),
      },
    );
  }

  if (value is bill_data.PastPaymentDataSellFfi) {
    return {
      'timeOfRequest': _simplify(value.timeOfRequest),
      'buyer': _simplify(value.buyer),
      'seller': _simplify(value.seller),
      'currency': value.currency,
      'sum': value.sum,
      'addressToPay': value.addressToPay,
      'privateDescriptorToSpend':
          value.privateDescriptorToSpend,
      'status': _simplify(value.status),
    };
  }

  if (value is bill_data.PastPaymentDataPaymentFfi) {
    return {
      'timeOfRequest': _simplify(value.timeOfRequest),
      'payer': _simplify(value.payer),
      'payee': _simplify(value.payee),
      'currency': value.currency,
      'sum': value.sum,
      'addressToPay': value.addressToPay,
      'privateDescriptorToSpend':
          value.privateDescriptorToSpend,
      'status': _simplify(value.status),
    };
  }

  if (value is bill_data.PastPaymentDataRecourseFfi) {
    return {
      'timeOfRequest': _simplify(value.timeOfRequest),
      'recourser': _simplify(value.recourser),
      'recoursee': _simplify(value.recoursee),
      'currency': value.currency,
      'sum': value.sum,
      'addressToPay': value.addressToPay,
      'privateDescriptorToSpend':
          value.privateDescriptorToSpend,
      'status': _simplify(value.status),
    };
  }

  if (value is bill_data.BillCombinedBitcoinKeyFfi) {
    return {
      'blockId': _simplify(value.blockId),
      'signingTimestamp':
          _simplify(value.signingTimestamp),
      'paymentOp': _simplify(value.paymentOp),
      'privateDescriptor': value.privateDescriptor,
    };
  }

  if (value is bill_data.BillSweepBTCEstimateFfi) {
    return {
      'availableFunds':
          _simplify(value.availableFunds),
      'economy': _simplify(value.economy),
      'fast': _simplify(value.fast),
    };
  }

  if (value is bill_data.BillSweepBTCOptionFfi) {
    return {
      'feeRateSatVb': value.feeRateSatVb,
      'feeSat': _simplify(value.feeSat),
      'amountToSweepSat':
          _simplify(value.amountToSweepSat),
    };
  }

  if (value is bill_data.BillSweepBTCFundsResultFfi) {
    return {
      'txId': value.txId,
      'linkToTx': value.linkToTx,
      'feeSat': _simplify(value.feeSat),
      'sweepAmount': _simplify(value.sweepAmount),
    };
  }

  if (value is mint_data.MintRequestStateResponse) {
    return value.requestStates.map(_simplify).toList();
  }
  if (value is mint_data.MintRequestStateFfi) {
    return {
      'request': _simplify(value.request),
      'offer': _simplify(value.offer),
    };
  }
  if (value is mint_data.MintRequestFfi) {
    return {
      'requesterNodeId': value.requesterNodeId,
      'billId': value.billId,
      'mintNodeId': value.mintNodeId,
      'mintRequestId': value.mintRequestId,
      'timestamp': value.timestamp.toString(),
      'status': '${value.status}',
    };
  }
  if (value is mint_data.MintOfferFfi) {
    return {
      'mintRequestId': value.mintRequestId,
      'keysetId': value.keysetId,
      'expirationTimestamp': value.expirationTimestamp.toString(),
      'discountedSum': value.discountedSum,
      'proofsSpent': value.proofsSpent,
      'proofs': value.proofs,
    };
  }

  if (value is notification_data.NotificationStatusFfi) {
    return {'nodeId': value.nodeId, 'active': value.active};
  }
  if (value is notification_data.NotificationFfi) {
    return {
      'id': value.id,
      'nodeId': value.nodeId,
      'type': '${value.notificationType}',
      'referenceId': value.referenceId,
      'description': value.description,
      'datetime': value.datetime,
      'active': value.active,
      'level': '${value.level}',
      'payload': value.payload,
    };
  }

  return '$value';
}

Map<String, Object?> _postal(dynamic address) {
  return {
    'country': address.country,
    'city': address.city,
    'zip': address.zip,
    'address': address.address,
  };
}

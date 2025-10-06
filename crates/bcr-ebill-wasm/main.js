import * as wasm from '../pkg/index.js';

// file upload
document.getElementById("fileInput").addEventListener("change", uploadFile);

// notifs
document.getElementById("notif").addEventListener("click", triggerNotif);
document.getElementById("get_active_notif_status").addEventListener("click", getActiveNotif);
document.getElementById("get_notif_list").addEventListener("click", getNotifList);
document.getElementById("register_email_notifications").addEventListener("click", register_email_notifications);
document.getElementById("get_email_notifications_preferences_link").addEventListener("click", get_email_notifications_preferences_link);

// contacts
document.getElementById("contact_test").addEventListener("click", triggerContact);
document.getElementById("contact_test_anon").addEventListener("click", triggerAnonContact);
document.getElementById("fetch_contacts").addEventListener("click", fetchContacts);
document.getElementById("remove_contact_avatar").addEventListener("click", removeContactAvatar);
document.getElementById("delete_contact").addEventListener("click", deleteContact);
document.getElementById("fetch_temp").addEventListener("click", fetchTempFile);
document.getElementById("fetch_contact_file").addEventListener("click", fetchContactFile);
document.getElementById("search_contacts").addEventListener("click", searchContacts);

// identity
document.getElementById("switch_identity").addEventListener("click", switchIdentity);
document.getElementById("share_contact_to").addEventListener("click", shareContact);
document.getElementById("dev_mode_get_identity_chain").addEventListener("click", devModeGetIdentityChain);

// identity proofs
document.getElementById("identity_proof_get_stamp").addEventListener("click", identityProofGetStamp);
document.getElementById("identity_proof_create").addEventListener("click", identityProofCreate);
document.getElementById("identity_proof_list").addEventListener("click", identityProofList);
document.getElementById("identity_proof_archive").addEventListener("click", identityProofArchive);
document.getElementById("identity_proof_re_check").addEventListener("click", identityProofReCheck);

// bill actions
document.getElementById("bill_fetch_detail").addEventListener("click", fetchBillDetail);
document.getElementById("bill_fetch_endorsements").addEventListener("click", fetchBillEndorsements);
document.getElementById("bill_fetch_past_endorsees").addEventListener("click", fetchBillPastEndorsees);
document.getElementById("bill_fetch_past_payments").addEventListener("click", fetchBillPastPayments);
document.getElementById("bill_fetch_bill_file").addEventListener("click", fetchBillFile);
document.getElementById("bill_fetch_bills").addEventListener("click", fetchBillBills);
document.getElementById("bill_balances").addEventListener("click", fetchBillBalances);
document.getElementById("bill_search").addEventListener("click", fetchBillSearch);
document.getElementById("endorse_bill").addEventListener("click", endorseBill);
document.getElementById("blank_endorse_bill").addEventListener("click", endorseBillBlank);
document.getElementById("req_to_accept_bill").addEventListener("click", requestToAcceptBill);
document.getElementById("accept_bill").addEventListener("click", acceptBill);
document.getElementById("req_to_pay_bill").addEventListener("click", requestToPayBill);
document.getElementById("offer_to_sell_bill").addEventListener("click", offerToSellBill);
document.getElementById("req_to_recourse_bill").addEventListener("click", requestToRecourseBill);
document.getElementById("req_to_recourse_bill_payment").addEventListener("click", requestToRecourseBillPayment);
document.getElementById("reject_accept").addEventListener("click", rejectAcceptBill);
document.getElementById("reject_pay").addEventListener("click", rejectPayBill);
document.getElementById("reject_buying").addEventListener("click", rejectBuyingBill);
document.getElementById("reject_recourse").addEventListener("click", rejectRecourseBill);
document.getElementById("request_to_mint").addEventListener("click", requestToMint);
document.getElementById("get_mint_state").addEventListener("click", getMintState);
document.getElementById("check_mint_state").addEventListener("click", checkMintState);
document.getElementById("cancel_req_to_mint").addEventListener("click", cancelRegToMint);
document.getElementById("accept_mint_offer").addEventListener("click", acceptMintOffer);
document.getElementById("reject_mint_offer").addEventListener("click", rejectMintOffer);
document.getElementById("bill_test_self_drafted").addEventListener("click", triggerBill.bind(null, 1, false));
document.getElementById("bill_test_promissory").addEventListener("click", triggerBill.bind(null, 0, false));
document.getElementById("bill_test_promissory_blank").addEventListener("click", triggerBill.bind(null, 0, true));
document.getElementById("clear_bill_cache").addEventListener("click", clearBillCache);
document.getElementById("sync_bill_chain").addEventListener("click", syncBillChain);
document.getElementById("dev_mode_get_bill_chain").addEventListener("click", devModeGetBillChain);
document.getElementById("share_bill_with_court").addEventListener("click", shareBillWithCourt);

// companies
document.getElementById("company_create").addEventListener("click", createCompany);
document.getElementById("company_update").addEventListener("click", updateCompany);
document.getElementById("company_add_signatory").addEventListener("click", addSignatory);
document.getElementById("company_remove_signatory").addEventListener("click", removeSignatory);
document.getElementById("company_list").addEventListener("click", listCompanies);
document.getElementById("share_company_contact_to").addEventListener("click", shareCompanyContact);
document.getElementById("dev_mode_get_company_chain").addEventListener("click", devModeGetCompanyChain);
document.getElementById("list_signatories").addEventListener("click", listSignatories);

// restore account, backup seed phrase
document.getElementById("get_seed_phrase").addEventListener("click", getSeedPhrase);
document.getElementById("restore_account").addEventListener("click", restoreFromSeedPhrase);


let config = {
  log_level: "debug",
  app_url: "https://bitcredit-dev.minibill.tech",
  // bitcoin_network: "regtest", // local reg test
  // esplora_base_url: "http://localhost:8094", // local reg test via docker-compose
  bitcoin_network: "testnet",
  esplora_base_url: "https://esplora.minibill.tech",
  nostr_relays: ["wss://bcr-relay-dev.minibill.tech"],
  // nostr_relays: ["ws://localhost:8080"],
  // if set to true we will drop DMs from nostr that we don't have in contacts
  nostr_only_known_contacts: false,
  job_runner_initial_delay_seconds: 1,
  job_runner_check_interval_seconds: 600,
  // default_mint_url: "http://localhost:4343",
  default_mint_url: "https://wildcat-dev-docker.minibill.tech",
  // default_mint_node_id: "bitcrt038d1bd3e2e3a01f20c861f18eb456cc33f869c9aaa5dec685f7f7d8c40ea3b3c7",
  default_mint_node_id: "bitcrt02a2e6ecd9dfee6f88e6a0eb8ebdcfa4dae9905158889586fc18bbcccbd9fac5e7", // dev mint
  num_confirmations_for_payment: 6,
  dev_mode: true,
  // default_court_url: "http://localhost:8000",
  default_court_url: "https://bcr-court-dev.minibill.tech"
};

async function start(create_identity) {
  await wasm.default();
  await wasm.initialize_api(config);

  let notificationApi = wasm.Api.notification();
  let identityApi = wasm.Api.identity();
  let identityProofApi = wasm.Api.identity_proof();
  let contactApi = wasm.Api.contact();
  let companyApi = wasm.Api.company();
  let billApi = wasm.Api.bill();
  let generalApi = wasm.Api.general();

  let bla = await identityApi.test_endpoint();
    console.log("RESRESRES", bla);

  let identity;
  let current_identity;
  // Identity
  try {
    identity = await identityApi.detail();
    console.log("local identity:", identity);
  } catch (err) {
    if (create_identity) {
      console.log("No local identity found - creating anon identity..");
      await identityApi.create({
        t: 1,
        name: "Cypherpunk",
        email: "cypher@example.com",
        postal_address: {},
      });

      identity = await identityApi.detail();

      console.log("Deanonymizing identity..");
      await identityApi.deanonymize({
        t: 0,
        name: "Johanna Smith",
        email: "jsmith@example.com",
        postal_address: {
          country: "AT",
          city: "Vienna",
          zip: "1020",
          address: "street 1",
        }
      });

      // add self to contacts
      await contactApi.create({
        t: 0,
        node_id: identity.node_id,
        name: "Self Contact",
        email: "selfcont@example.com",
        postal_address: {
          country: "AT",
          city: "Vienna",
          zip: "1020",
          address: "street 1",
        },
      });
    }
  }

  if (identity) {
    document.getElementById("identity").innerHTML = identity.node_id;

    await notificationApi.subscribe((evt) => {
      console.log("Received event in JS: ", evt);
    });

    current_identity = await identityApi.active();
    console.log(current_identity);
    document.getElementById("current_identity").innerHTML = current_identity.node_id;

    // Company
    let companies = await companyApi.list();
    console.log("companies:", companies.companies.length, companies);
    if (companies.companies.length == 0 && create_identity) {
      let company = await companyApi.create({
        name: "hayek Ltd",
        email: "test@example.com",
        postal_address: {
          country: "AT",
          city: "Vienna",
          zip: "1020",
          address: "street 1",
        }
      });
      console.log("company: ", company);
      await companyApi.edit({ id: company.id, email: "different@example.com", postal_address: {} });
      let detail = await companyApi.detail(company.id);
      console.log("company detail: ", detail);
      // add company to contacts
      await contactApi.create({
        t: 1,
        node_id: detail.id,
        name: "Company Contact",
        email: "comcont@example.com",
        postal_address: {
          country: "AT",
          city: "Vienna",
          zip: "1020",
          address: "street 1",
        },
      });
    } else if (companies.companies.length > 0) {
      document.getElementById("companies").innerHTML = "node_id: " + companies.companies[0].id;
    }
  }

  // General
  let currencies = await generalApi.currencies();
  console.log("currencies: ", currencies);

  let status = await generalApi.status();
  console.log("status: ", status);

  if (identity) {
    let search = await generalApi.search({ filter: { search_term: "Test", currency: "sat", item_types: ["Contact"] } });
    console.log("search: ", search);
  }

  // Notifications
  if (current_identity) {
    let filter = current_identity ? { node_ids: [current_identity.node_id] } : null;
    let notifications = await notificationApi.list(filter);
    console.log("notifications: ", notifications);
  }
  console.log("Returning apis..");
  return { companyApi, generalApi, identityApi, billApi, contactApi, notificationApi, identityProofApi };
}

let apis = await start(generateIdentity());
let contactApi = apis.contactApi;
let companyApi = apis.companyApi;
let generalApi = apis.generalApi;
let identityApi = apis.identityApi;
let identityProofApi = apis.identityProofApi;
let billApi = apis.billApi;
window.billApi = billApi;
window.identityApi = identityApi;
window.generalApi = generalApi;
let notificationTriggerApi = apis.notificationApi;
console.log("Apis initialized..");


async function uploadFile(event) {
  const file = event.target.files[0];
  if (!file) return;

  const name = file.name;
  const extension = name.split('.').pop();

  const bytes = await file.arrayBuffer();
  const data = new Uint8Array(bytes);

  const uploadedFile = { name, extension, data };

  console.log("File Name:", uploadedFile.name);
  console.log("File Extension:", uploadedFile.extension);
  console.log("File Bytes:", uploadedFile.data);
  try {
    let file_upload_response = await contactApi.upload(uploadedFile);
    console.log("success uploading:", file_upload_response);
    document.getElementById("file_upload_id").value = file_upload_response.file_upload_id;
  } catch (err) {
    console.log("upload error: ", err);
  }
}

async function getSeedPhrase() {
  let seed_phrase = await identityApi.seed_backup();
  document.getElementById("current_seed").innerHTML = seed_phrase.seed_phrase;
}

async function restoreFromSeedPhrase() {
  let seed_phrase = document.getElementById("restore_seed_phrase").value;
  await identityApi.seed_recover({ seed_phrase });
}

async function createCompany() {
  let company = await companyApi.create({
    name: "hayek Ltd",
    email: "test@example.com",
    postal_address: {
      country: "AT",
      city: "Vienna",
      zip: "1020",
      address: "street 1",
    }
  });
  console.log("company: ", company);
}

async function updateCompany() {
  let company_id = document.getElementById("company_update_id").value;
  let name = document.getElementById("company_update_name").value;
  await companyApi.edit({
    id: company_id,
    name: name,
    postal_address: {}
  });
  console.log("updated company name: ", company_id, name);
}

async function addSignatory() {
  let company_id = document.getElementById("company_update_id").value;
  let signatory_node_id = document.getElementById("company_signatory_id").value;
  await companyApi.add_signatory({
    id: company_id,
    signatory_node_id: signatory_node_id,
  });
  console.log("added signatory to company: ", signatory_node_id, company_id);
}

async function removeSignatory() {
  let company_id = document.getElementById("company_update_id").value;
  let signatory_node_id = document.getElementById("company_signatory_id").value;
  await companyApi.remove_signatory({
    id: company_id,
    signatory_node_id: signatory_node_id,
  });
  console.log("removed signatory to company: ", signatory_node_id, company_id);
}

async function shareCompanyContact() {
  let node_id = document.getElementById("company_update_id").value;
  let share_to_node_id = document.getElementById("company_signatory_id").value;
  console.log("sharing contact details to identity: ", node_id);
  await companyApi.share_contact_details({ recipient: share_to_node_id, company_id: node_id });
}

async function listCompanies() {
  let companies = await companyApi.list();
  console.log("companies:", companies.companies.length, companies);
}

async function listSignatories() {
  let signatories = await companyApi.list_signatories(document.getElementById("company_update_id").value);
  console.log("signatories:", signatories);
}

async function triggerContact() {
  let node_id = document.getElementById("node_id_contact").value;
  try {
    let contact = await contactApi.detail(node_id);
    console.log("contact:", contact);
  } catch (err) {
    console.log("No contact found - creating..");
    let file_upload_id = document.getElementById("file_upload_id").value || undefined;
    await contactApi.create({
      t: 0,
      node_id: node_id,
      name: "Test Contact",
      email: "text@example.com",
      postal_address: {
        country: "AT",
        city: "Vienna",
        zip: "1020",
        address: "street 1",
      },
      avatar_file_upload_id: file_upload_id,
    });
  }
  let contact = await contactApi.detail(node_id);
  console.log("contact:", contact);
  document.getElementById("contact_id").value = node_id;
  document.getElementById("node_id_bill").value = node_id;
  if (contact.avatar_file) {
    document.getElementById("contact_file_name").value = contact.avatar_file.name;
  }
}

async function triggerAnonContact() {
  let node_id = document.getElementById("node_id_contact").value;
  try {
    let contact = await contactApi.detail(node_id);
    console.log("anon contact:", contact);
  } catch (err) {
    console.log("No contact found - creating..");
    await contactApi.create({
      t: 2,
      node_id: node_id,
      name: "some anon dude",
      email: "text@example.com",
    });
  }
  document.getElementById("contact_id").value = node_id;
  document.getElementById("node_id_bill").value = node_id;
}

async function triggerBill(t, blank) {
  let measured = measure(async () => {
    console.log("creating bill");

    const now = new Date();
    const issue_date = now.toISOString().split('T')[0];
    const nMonthsLater = new Date(now);
    nMonthsLater.setMonth(now.getMonth() + 3); // use to set maturity date after issue date
    const maturity_date = nMonthsLater.toISOString().split('T')[0];

    let file_upload_id = document.getElementById("file_upload_id").value || undefined;
    let node_id = document.getElementById("node_id_bill").value;
    let identity = await identityApi.detail();
    let bill_issue_data = {
      t,
      country_of_issuing: "AT",
      city_of_issuing: "Vienna",
      issue_date,
      maturity_date,
      payee: t == 0 ? node_id : identity.node_id,
      drawee: t == 0 ? identity.node_id : node_id,
      sum: "1500",
      currency: "sat",
      country_of_payment: "UK",
      city_of_payment: "London",
      language: "en-UK",
      file_upload_ids: file_upload_id ? [file_upload_id] : []
    };
    let bill;
    if (blank) {
      bill = await billApi.issue_blank(bill_issue_data);
    } else {
      bill = await billApi.issue(bill_issue_data);
    }
    let bill_id = bill.id;
    console.log("created bill with id: ", bill_id);
  });
  await measured();
}

async function triggerNotif() {
  await notificationTriggerApi.trigger_test_msg({ test: "Hello, World" });
}

async function fetchTempFile() {
  let file_upload_id = document.getElementById("file_upload_id").value;
  let temp_file = await generalApi.temp_file(file_upload_id);
  let file_bytes = temp_file.data;
  let arr = new Uint8Array(file_bytes);
  let blob = new Blob([arr], { type: temp_file.content_type });
  let url = URL.createObjectURL(blob);

  console.log("file", temp_file, url, blob);
  document.getElementById("uploaded_file").src = url;
}

async function fetchContactFile() {
  let node_id = document.getElementById("contact_id").value;
  let file_name = document.getElementById("contact_file_name").value;
  let file = await contactApi.file_base64(node_id, file_name);
  document.getElementById("attached_file").src = `data:${file.content_type};base64,${file.data}`;
}

async function switchIdentity() {
  let node_id = document.getElementById("node_id_identity").value;
  await identityApi.switch({ t: 1, node_id });
  document.getElementById("current_identity").textContent = node_id;
}

async function shareContact() {
  let node_id = document.getElementById("node_id_identity").value;
  console.log("sharing contact details to identity: ", node_id);
  await identityApi.share_contact_details({ recipient: node_id });
}

async function identityProofGetStamp() {
  let stamp = await identityProofApi.get_identity_stamp();
  document.getElementById("identity_proof_stamp").value = stamp;
}

async function identityProofCreate() {
  let stamp = document.getElementById("identity_proof_stamp").value;
  let url = document.getElementById("identity_proof_url").value;
  let identity_proof = await identityProofApi.add(url, stamp);
  document.getElementById("identity_proof_id").value = identity_proof.id;
}
async function identityProofList() {
  let measured = measure(async () => {
    return await identityProofApi.list();
  });
  await measured();
}
async function identityProofArchive() {
  let id = document.getElementById("identity_proof_id").value;
  await identityProofApi.archive(id);
}
async function identityProofReCheck() {
  let id = document.getElementById("identity_proof_id").value;
  let identity_proof = await identityProofApi.re_check(id);
}

async function endorseBill() {
  let bill_id = document.getElementById("endorse_bill_id").value;
  let endorsee = document.getElementById("endorsee_id").value;
  let measured = measure(async () => {
    return await billApi.endorse_bill({ bill_id, endorsee });
  });
  await measured();
}

async function endorseBillBlank() {
  let bill_id = document.getElementById("endorse_bill_id").value;
  let endorsee = document.getElementById("endorsee_id").value;
  let measured = measure(async () => {
    return await billApi.endorse_bill_blank({ bill_id, endorsee });
  });
  await measured();
}

async function requestToAcceptBill() {
  let bill_id = document.getElementById("endorse_bill_id").value;
  let measured = measure(async () => {
    return await billApi.request_to_accept({ bill_id });
  });
  await measured();
}

async function acceptBill() {
  let bill_id = document.getElementById("endorse_bill_id").value;
  let measured = measure(async () => {
    return await billApi.accept({ bill_id });
  });
  await measured();
}

async function requestToPayBill() {
  let bill_id = document.getElementById("endorse_bill_id").value;
  let measured = measure(async () => {
    return await billApi.request_to_pay({ bill_id, currency: "sat" });
  });
  await measured();
}

async function offerToSellBill() {
  let bill_id = document.getElementById("endorse_bill_id").value;
  let endorsee = document.getElementById("endorsee_id").value;
  let measured = measure(async () => {
    return await billApi.offer_to_sell({ bill_id, sum: "500", currency: "sat", buyer: endorsee });
  });
  await measured();
}

async function requestToRecourseBill() {
  let bill_id = document.getElementById("endorse_bill_id").value;
  let endorsee = document.getElementById("endorsee_id").value;
  let measured = measure(async () => {
    return await billApi.request_to_recourse_bill_acceptance({ bill_id, recoursee: endorsee });
  });
  await measured();
}

async function requestToRecourseBillPayment() {
  let bill_id = document.getElementById("endorse_bill_id").value;
  let endorsee = document.getElementById("endorsee_id").value;
  let measured = measure(async () => {
    return await billApi.request_to_recourse_bill_payment({ bill_id, recoursee: endorsee, currency: "sat", sum: "1500" });
  });
  await measured();
}

async function rejectAcceptBill() {
  let bill_id = document.getElementById("endorse_bill_id").value;
  let measured = measure(async () => {
    return await billApi.reject_to_accept({ bill_id });
  });
  await measured();
}

async function rejectPayBill() {
  let bill_id = document.getElementById("endorse_bill_id").value;
  let measured = measure(async () => {
    return await billApi.reject_to_pay({ bill_id });
  });
  await measured();
}

async function rejectBuyingBill() {
  let bill_id = document.getElementById("endorse_bill_id").value;
  let measured = measure(async () => {
    return await billApi.reject_to_buy({ bill_id });
  });
  await measured();
}

async function rejectRecourseBill() {
  let bill_id = document.getElementById("endorse_bill_id").value;
  let measured = measure(async () => {
    return await billApi.reject_to_pay_recourse({ bill_id });
  });
  await measured();
}

async function requestToMint() {
  let bill_id = document.getElementById("endorse_bill_id").value;
  let measured = measure(async () => {
    return await billApi.request_to_mint({ bill_id, mint_node: config.default_mint_node_id });
  });
  await measured();
}

async function getMintState() {
  let bill_id = document.getElementById("endorse_bill_id").value;
  let measured = measure(async () => {
    return await billApi.mint_state(bill_id);
  });
  await measured();
}

async function checkMintState() {
  let bill_id = document.getElementById("endorse_bill_id").value;
  let measured = measure(async () => {
    return await billApi.check_mint_state(bill_id);
  });
  await measured();
}

async function cancelRegToMint() {
  let mint_request_id = document.getElementById("mint_req_id").value;
  let measured = measure(async () => {
    return await billApi.cancel_request_to_mint(mint_request_id);
  });
  await measured();
}

async function acceptMintOffer() {
  let mint_request_id = document.getElementById("mint_req_id").value;
  let measured = measure(async () => {
    return await billApi.accept_mint_offer(mint_request_id);
  });
  await measured();
}

async function rejectMintOffer() {
  let mint_request_id = document.getElementById("mint_req_id").value;
  let measured = measure(async () => {
    return await billApi.reject_mint_offer(mint_request_id);
  });
  await measured();
}

async function fetchBillDetail() {
  let measured = measure(async () => {
    return await billApi.detail(document.getElementById("bill_id").value);
  });
  await measured();
}

async function fetchBillEndorsements() {
  let measured = measure(async () => {
    return await billApi.endorsements(document.getElementById("bill_id").value);
  });
  await measured();
}

async function fetchBillPastEndorsees() {
  let measured = measure(async () => {
    return await billApi.past_endorsees(document.getElementById("bill_id").value);
  });
  await measured();
}

async function fetchBillPastPayments() {
  let measured = measure(async () => {
    return await billApi.past_payments(document.getElementById("bill_id").value);
  });
  await measured();
}

async function fetchBillFile() {
  let bill_id = document.getElementById("bill_id").value;
  let detail = await billApi.detail(bill_id);

  if (detail.data.files.length > 0) {
    let file = await billApi.attachment_base64(bill_id, detail.data.files[0].name);
    document.getElementById("bill_attached_file").src = `data:${file.content_type};base64,${file.data}`;
  } else {
    console.log("Bill has no file");
  }
}

async function fetchBillBills() {
  let measured = measure(async () => {
    return await billApi.list();
  });
  await measured();
}

async function fetchBillBalances() {
  let measured = measure(async () => {
    return await generalApi.overview("sat");
  });
  await measured();
}

async function fetchBillSearch() {
  let measured = measure(async () => {
    return await billApi.search({ filter: { currency: "sat", role: "All" } });
  });
  await measured();
}

async function clearBillCache() {
  let measured = measure(async () => {
    return await billApi.clear_bill_cache();
  });
  await measured();
}

async function syncBillChain() {
  let bill_id = document.getElementById("bill_id").value;
  console.log("syncBillChain", bill_id);
  let measured = measure(async () => {
    return await billApi.sync_bill_chain({ bill_id: bill_id });
  });
  await measured();
}

async function shareBillWithCourt() {
  let bill_id = document.getElementById("court_bill_id").value;
  let court_node_id = document.getElementById("court_node_id").value;
  let measured = measure(async () => {
    return await billApi.share_bill_with_court({ bill_id: bill_id, court_node_id: court_node_id });
  });
  await measured();
}

async function devModeGetBillChain() {
  let bill_id = document.getElementById("dev_mode_bill_id").value;
  console.log("devModeGetBillChain", bill_id);
  let measured = measure(async () => {
    let res = await billApi.dev_mode_get_full_bill_chain(bill_id);
    return res.map((b) => {
      const block = JSON.parse(b);
      return { ...block, data: JSON.parse(block.data) };
    })
  });
  await measured();
}

async function devModeGetIdentityChain() {
  console.log("devModeGetIdentityChain");
  let measured = measure(async () => {
    let res = await identityApi.dev_mode_get_full_identity_chain();
    return res.map((b) => {
      const block = JSON.parse(b);
      return { ...block, data: JSON.parse(block.data) };
    })
  });
  await measured();
}

async function devModeGetCompanyChain() {
  let company_id = document.getElementById("dev_mode_company_id").value;
  console.log("devModeGetCompanyChain", company_id);
  let measured = measure(async () => {
    let res = await companyApi.dev_mode_get_full_company_chain(company_id);
    return res.map((b) => {
      const block = JSON.parse(b);
      return { ...block, data: JSON.parse(block.data) };
    })
  });
  await measured();
}

function measure(promiseFunction) {
  return async function (...args) {
    const startTime = performance.now();
    const result = await promiseFunction(...args);
    const endTime = performance.now();
    const exec_time = (endTime - startTime).toFixed(2);
    console.log(`Execution time: ${exec_time} ms`);

    document.getElementById("bill_execution_time").innerHTML = `${exec_time} ms`;
    document.getElementById("bill_results").innerHTML = "<pre>" + JSON.stringify(result, null, 2) + "</pre>";

    return result;
  };
}

async function fetchContacts() {
  let measured = measure(async () => {
    return await contactApi.list();
  });
  await measured();
}

async function searchContacts() {
  let measured = measure(async () => {
    return await contactApi.search({
      search_term: document.getElementById("contact_search_term").value,
      include_logical: true,
      include_contact: true
    });
  });
  await measured();
}

async function removeContactAvatar() {
  let node_id = document.getElementById("node_id_contact").value;
  let measured = measure(async () => {
    return await contactApi.edit({ node_id: node_id, avatar_file_upload_id: undefined, postal_address: {} });
  });
  await measured();
}

async function deleteContact() {
  let node_id = document.getElementById("node_id_contact").value;
  let measured = measure(async () => {
    return await contactApi.remove(node_id);
  });
  await measured();
}

async function getActiveNotif() {
  let measured = measure(async () => {
    return await notificationTriggerApi.active_notifications_for_node_ids([]);
  });
  await measured();
}

async function getNotifList() {
  let measured = measure(async () => {
    return await notificationTriggerApi.list({});
  });
  await measured();
}

async function register_email_notifications() {
  let measured = measure(async () => {
    return await notificationTriggerApi.register_email_notifications(config.nostr_relays[0]);
  });
  await measured();
}

async function get_email_notifications_preferences_link() {
  let measured = measure(async () => {
    return await notificationTriggerApi.get_email_notifications_preferences_link();
  });
  await measured();
}

// disables auto identity creation via query param identity=false
function generateIdentity() {
  let param = getQueryParam("identity");
  if (param && param.toLowerCase() === "false") {
    return false;
  }
  return true;
}

function getQueryParam(paramName) {
  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.get(paramName);
}


import React, { useContext } from "react";
import { MainContext } from "../../context/MainContext";
import SingleBillDetail from "../popups/SingleBillDetail";

const signCalculation = (peer_id, items) => {
  if (peer_id == items.drawee.peer_id) {
    //   name = `${items?.drawee?.name} has to pay ${items?.payee?.name}`;
    return "-";
  } else if (
    peer_id != items.payee.peer_id &&
    peer_id != items.endorsee.peer_id &&
    peer_id != items.drawee.peer_id
  ) {
    //   name = `${items.drawee.name} ${items.payee.name}`;
    return "x";
  } else if (peer_id == items.payee.peer_id) {
    //   name = `${items.drawee.name} ${items.payee.name}`;
    return "+";
  } else if (peer_id == items.endorsee.peer_id) {
    //   name = `${items.drawee.name} ${items.payee.name}`;
    return "+";
  }
  if (peer_id == items.drawee.peer_id) {
    //   name = `${items?.drawee?.name} has to pay ${items?.payee?.name}`;
    return "-";
  } else if (
    peer_id != items.payee.peer_id &&
    peer_id != items.endorsee.peer_id &&
    peer_id != items.drawee.peer_id
  ) {
    //   name = `${items.drawee.name} ${items.payee.name}`;
    return "x";
  } else if (peer_id == items.payee.peer_id) {
    //   name = `${items.drawee.name} ${items.payee.name}`;
    return "+";
  } else if (peer_id == items.endorsee.peer_id) {
    //   name = `${items.drawee.name} ${items.payee.name}`;
    return "+";
  }
};
const namehandling = (peer_id, items) => {
  if (peer_id == items?.payee?.peer_id) {
    return items?.payee?.name;
  } else if (peer_id == items?.drawee?.peer_id) {
    return items?.drawee?.name;
  } else {
    return items?.drawee?.name;
  }
};
const getIcon = (peer_id, payerId, payeeId, keys) => {
  let payee = peer_id === payeeId;
  let payer = peer_id === payerId;
  let AcceptedYellow =
    !keys?.accepted &&
    !keys?.requested_to_accept &&
    !keys?.payed &&
    !keys.requested_to_pay &&
    (payer || payee);
  let AcceptedRed =
    !keys?.accepted &&
    keys?.requested_to_accept &&
    !keys?.payed &&
    !keys.requested_to_pay &&
    (payer || payee);
  let PayYellow =
    keys?.accepted &&
    !keys?.payed &&
    !keys.requested_to_pay &&
    (payer || payee);
  let PayRed = !keys?.payed && keys.requested_to_pay && (payer || payee);
  let PayGreen = keys?.payed && (payer || payee);

  if (AcceptedYellow) {
    return (
      <svg
        width="24"
        height="24"
        viewBox="0 0 24 24"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <path
          fill-rule="evenodd"
          clip-rule="evenodd"
          d="M2 4.5C2 3.11928 3.11928 2 4.5 2H19.5C20.8807 2 22 3.11928 22 4.5V14.4547C21.0165 13.1622 19.4619 12.3278 17.7123 12.3278C14.7384 12.3278 12.3278 14.7384 12.3278 17.7123C12.3278 19.4619 13.1622 21.0165 14.4547 22H4.5C3.11928 22 2 20.8807 2 19.5V4.5ZM10.9429 15.676L16.4202 9.15546C16.5285 9.0227 16.5802 8.85262 16.5641 8.68213C16.548 8.51154 16.4654 8.35417 16.3343 8.244C16.2031 8.13383 16.0338 8.07971 15.8631 8.09324C15.7583 8.10158 15.6581 8.13505 15.5705 8.18958C15.5152 8.22396 15.465 8.26668 15.4217 8.31673L10.4257 14.2632L8.57989 12.2124C8.54215 12.1684 8.49862 12.1296 8.45081 12.0972C8.427 12.0812 8.40218 12.0666 8.37634 12.0537C8.29852 12.015 8.21379 11.9921 8.12712 11.9865C8.04034 11.9809 7.95337 11.9927 7.87128 12.0213C7.78918 12.0497 7.7136 12.0944 7.64901 12.1525C7.60801 12.1894 7.572 12.2312 7.54169 12.2769C7.52419 12.3032 7.50863 12.3309 7.4951 12.3597C7.45817 12.4384 7.43722 12.5237 7.43365 12.6105C7.43009 12.6973 7.44393 12.784 7.47434 12.8654C7.50476 12.9468 7.55115 13.0213 7.61076 13.0845L9.95817 15.6928C10.0193 15.7608 10.0941 15.8151 10.1775 15.8523C10.2232 15.8726 10.2708 15.8876 10.3196 15.897C10.3601 15.9048 10.4013 15.9088 10.4428 15.9088H10.4538C10.5472 15.9073 10.6392 15.8858 10.7237 15.8456C10.781 15.8183 10.834 15.7828 10.881 15.7403C10.903 15.7204 10.9236 15.6989 10.9429 15.676Z"
          fill="yellow"
        />
        <path
          fill-rule="evenodd"
          clip-rule="evenodd"
          d="M17.7123 21.9996C20.0802 21.9996 21.9998 20.08 21.9998 17.7121C21.9998 15.3441 20.0802 13.4246 17.7123 13.4246C15.3443 13.4246 13.4248 15.3441 13.4248 17.7121C13.4248 20.08 15.3443 21.9996 17.7123 21.9996ZM17.2859 18.6214H18.1384L18.4811 15.1321H16.9433L17.2859 18.6214ZM18.3668 19.6494C18.3668 20.0138 18.0737 20.3092 17.7121 20.3092C17.3506 20.3092 17.0575 20.0138 17.0575 19.6494C17.0575 19.2851 17.3506 18.9897 17.7121 18.9897C18.0737 18.9897 18.3668 19.2851 18.3668 19.6494Z"
          fill="yellow"
        />
      </svg>
    );
  } else if (AcceptedRed) {
    return (
      <svg
        width="24"
        height="24"
        viewBox="0 0 24 24"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <path
          fill-rule="evenodd"
          clip-rule="evenodd"
          d="M2 4.5C2 3.11928 3.11928 2 4.5 2H19.5C20.8807 2 22 3.11928 22 4.5V14.4547C21.0165 13.1622 19.4619 12.3278 17.7123 12.3278C14.7384 12.3278 12.3278 14.7384 12.3278 17.7123C12.3278 19.4619 13.1622 21.0165 14.4547 22H4.5C3.11928 22 2 20.8807 2 19.5V4.5ZM10.9429 15.676L16.4202 9.15546C16.5285 9.0227 16.5802 8.85262 16.5641 8.68213C16.548 8.51154 16.4654 8.35417 16.3343 8.244C16.2031 8.13383 16.0338 8.07971 15.8631 8.09324C15.7583 8.10158 15.6581 8.13505 15.5705 8.18958C15.5152 8.22396 15.465 8.26668 15.4217 8.31673L10.4257 14.2632L8.57989 12.2124C8.54215 12.1684 8.49862 12.1296 8.45081 12.0972C8.427 12.0812 8.40218 12.0666 8.37634 12.0537C8.29852 12.015 8.21379 11.9921 8.12712 11.9865C8.04034 11.9809 7.95337 11.9927 7.87128 12.0213C7.78918 12.0497 7.7136 12.0944 7.64901 12.1525C7.60801 12.1894 7.572 12.2312 7.54169 12.2769C7.52419 12.3032 7.50863 12.3309 7.4951 12.3597C7.45817 12.4384 7.43722 12.5237 7.43365 12.6105C7.43009 12.6973 7.44393 12.784 7.47434 12.8654C7.50476 12.9468 7.55115 13.0213 7.61076 13.0845L9.95817 15.6928C10.0193 15.7608 10.0941 15.8151 10.1775 15.8523C10.2232 15.8726 10.2708 15.8876 10.3196 15.897C10.3601 15.9048 10.4013 15.9088 10.4428 15.9088H10.4538C10.5472 15.9073 10.6392 15.8858 10.7237 15.8456C10.781 15.8183 10.834 15.7828 10.881 15.7403C10.903 15.7204 10.9236 15.6989 10.9429 15.676Z"
          fill="#d30000"
        />
        <path
          fill-rule="evenodd"
          clip-rule="evenodd"
          d="M17.7123 21.9996C20.0802 21.9996 21.9998 20.08 21.9998 17.7121C21.9998 15.3441 20.0802 13.4246 17.7123 13.4246C15.3443 13.4246 13.4248 15.3441 13.4248 17.7121C13.4248 20.08 15.3443 21.9996 17.7123 21.9996ZM17.2859 18.6214H18.1384L18.4811 15.1321H16.9433L17.2859 18.6214ZM18.3668 19.6494C18.3668 20.0138 18.0737 20.3092 17.7121 20.3092C17.3506 20.3092 17.0575 20.0138 17.0575 19.6494C17.0575 19.2851 17.3506 18.9897 17.7121 18.9897C18.0737 18.9897 18.3668 19.2851 18.3668 19.6494Z"
          fill="#d30000"
        />
      </svg>
    );
  } else if (PayYellow) {
    return (
      <svg
        width="20"
        height="20"
        viewBox="0 0 20 20"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <path
          d="M1.75577 4.05495C1.91903 3.62801 2.39747 3.41426 2.8244 3.57752L4.36121 4.16518C4.78814 4.32844 5.0019 4.80688 4.83864 5.23381L3.24791 9.39375C3.08465 9.82068 2.60621 10.0344 2.17928 9.87118L0.642471 9.28351C0.215539 9.12026 0.00178741 8.64182 0.165043 8.21488L1.75577 4.05495Z"
          fill="yellow"
        />
        <path
          d="M3.74081 9.06138L5.05189 5.63277C5.14984 5.37661 5.43741 5.25266 5.70759 5.29971C7.29337 5.5759 9.09032 4.47109 10.8711 4.98027C12.8336 5.54139 15.4684 7.38981 16.6803 8.26454C15.4132 7.96426 14.2628 8.49171 13.846 8.79297L9.30455 8.53699C9.94649 8.65085 11.442 8.91016 12.2887 9.03649C13.347 9.19441 16.2311 9.31018 16.0491 10.4745C15.8671 11.6387 14.7793 11.6011 11.9834 11.4697C9.18752 11.3384 8.88607 12.3418 7.33215 12.0602C5.77824 11.7785 4.69463 10.5251 4.46331 10.1406C4.37871 9.9999 4.22653 9.8843 4.06418 9.79494C3.80156 9.65041 3.63375 9.34137 3.74081 9.06138Z"
          fill="yellow"
        />
        <path
          d="M9.58415 13.0414C9.2684 13.0167 8.96246 12.5866 8.84896 12.3746C9.21944 12.2507 9.78637 12.0764 10.2985 11.9909C10.7083 11.9224 11.39 11.9531 11.6796 11.977C11.6571 12.2359 11.6449 12.9018 11.7769 13.4942C11.0187 13.4711 10.6583 12.858 10.5729 12.5544C10.3749 12.727 9.8999 13.0661 9.58415 13.0414Z"
          fill="yellow"
        />
        <path
          fill-rule="evenodd"
          clip-rule="evenodd"
          d="M18.5383 15.5019C16.895 16.9373 14.3995 16.7689 12.964 15.1258C12.1784 14.2266 11.8732 13.072 12.0272 11.9757C12.993 11.9928 13.9691 12.0053 14.7323 11.8785C14.9182 11.8477 15.1041 11.8068 15.2826 11.7508C15.3489 12.0678 15.5117 12.386 15.658 12.6716C15.9898 13.3062 16.1109 13.6374 15.8487 13.8664C15.5915 14.0912 15.0869 13.9563 14.7476 13.5678C14.4082 13.1793 14.3423 12.6613 14.5996 12.4365L14.1833 11.9598C13.7566 12.3324 13.7004 12.9993 14.0015 13.5893L13.4821 14.0431L14.1067 14.758L14.6261 14.3042C15.1703 14.6817 15.8385 14.7157 16.2653 14.3431C16.9277 13.7642 16.5353 12.9976 16.2204 12.382C16.0033 11.967 15.8764 11.6817 15.8879 11.47C15.8967 11.4641 15.9055 11.458 15.9143 11.452C16.0629 11.3483 16.1915 11.2244 16.294 11.0808C16.5557 11.0576 16.8862 11.2059 17.1307 11.4858C17.4702 11.8743 17.536 12.3923 17.2787 12.6171L17.695 13.0939C18.1218 12.7212 18.1779 12.0543 17.8768 11.4644L18.3962 11.0106L17.7717 10.2956L17.2522 10.7494C17.0288 10.5943 16.7843 10.4971 16.5443 10.4625C16.5506 10.4221 16.5555 10.3809 16.5589 10.3387C16.5974 9.86082 16.3652 9.49948 16.0364 9.26625C15.7427 9.05789 15.3592 8.93785 14.9851 8.85448C14.8811 8.83115 14.7712 8.80968 14.6563 8.78933C16.1294 8.28422 17.8264 8.68264 18.9143 9.92781C20.3498 11.5709 20.1814 14.0665 18.5383 15.5019Z"
          fill="yellow"
        />
      </svg>
    );
  } else if (PayRed) {
    return (
      <svg
        width="20"
        height="20"
        viewBox="0 0 20 20"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <path
          d="M1.75577 4.05495C1.91903 3.62801 2.39747 3.41426 2.8244 3.57752L4.36121 4.16518C4.78814 4.32844 5.0019 4.80688 4.83864 5.23381L3.24791 9.39375C3.08465 9.82068 2.60621 10.0344 2.17928 9.87118L0.642471 9.28351C0.215539 9.12026 0.00178741 8.64182 0.165043 8.21488L1.75577 4.05495Z"
          fill="#d30000"
        />
        <path
          d="M3.74081 9.06138L5.05189 5.63277C5.14984 5.37661 5.43741 5.25266 5.70759 5.29971C7.29337 5.5759 9.09032 4.47109 10.8711 4.98027C12.8336 5.54139 15.4684 7.38981 16.6803 8.26454C15.4132 7.96426 14.2628 8.49171 13.846 8.79297L9.30455 8.53699C9.94649 8.65085 11.442 8.91016 12.2887 9.03649C13.347 9.19441 16.2311 9.31018 16.0491 10.4745C15.8671 11.6387 14.7793 11.6011 11.9834 11.4697C9.18752 11.3384 8.88607 12.3418 7.33215 12.0602C5.77824 11.7785 4.69463 10.5251 4.46331 10.1406C4.37871 9.9999 4.22653 9.8843 4.06418 9.79494C3.80156 9.65041 3.63375 9.34137 3.74081 9.06138Z"
          fill="#d30000"
        />
        <path
          d="M9.58415 13.0414C9.2684 13.0167 8.96246 12.5866 8.84896 12.3746C9.21944 12.2507 9.78637 12.0764 10.2985 11.9909C10.7083 11.9224 11.39 11.9531 11.6796 11.977C11.6571 12.2359 11.6449 12.9018 11.7769 13.4942C11.0187 13.4711 10.6583 12.858 10.5729 12.5544C10.3749 12.727 9.8999 13.0661 9.58415 13.0414Z"
          fill="#d30000"
        />
        <path
          fill-rule="evenodd"
          clip-rule="evenodd"
          d="M18.5383 15.5019C16.895 16.9373 14.3995 16.7689 12.964 15.1258C12.1784 14.2266 11.8732 13.072 12.0272 11.9757C12.993 11.9928 13.9691 12.0053 14.7323 11.8785C14.9182 11.8477 15.1041 11.8068 15.2826 11.7508C15.3489 12.0678 15.5117 12.386 15.658 12.6716C15.9898 13.3062 16.1109 13.6374 15.8487 13.8664C15.5915 14.0912 15.0869 13.9563 14.7476 13.5678C14.4082 13.1793 14.3423 12.6613 14.5996 12.4365L14.1833 11.9598C13.7566 12.3324 13.7004 12.9993 14.0015 13.5893L13.4821 14.0431L14.1067 14.758L14.6261 14.3042C15.1703 14.6817 15.8385 14.7157 16.2653 14.3431C16.9277 13.7642 16.5353 12.9976 16.2204 12.382C16.0033 11.967 15.8764 11.6817 15.8879 11.47C15.8967 11.4641 15.9055 11.458 15.9143 11.452C16.0629 11.3483 16.1915 11.2244 16.294 11.0808C16.5557 11.0576 16.8862 11.2059 17.1307 11.4858C17.4702 11.8743 17.536 12.3923 17.2787 12.6171L17.695 13.0939C18.1218 12.7212 18.1779 12.0543 17.8768 11.4644L18.3962 11.0106L17.7717 10.2956L17.2522 10.7494C17.0288 10.5943 16.7843 10.4971 16.5443 10.4625C16.5506 10.4221 16.5555 10.3809 16.5589 10.3387C16.5974 9.86082 16.3652 9.49948 16.0364 9.26625C15.7427 9.05789 15.3592 8.93785 14.9851 8.85448C14.8811 8.83115 14.7712 8.80968 14.6563 8.78933C16.1294 8.28422 17.8264 8.68264 18.9143 9.92781C20.3498 11.5709 20.1814 14.0665 18.5383 15.5019Z"
          fill="#d30000"
        />
      </svg>
    );
  } else if (PayGreen) {
    return (
      <svg
        width="20"
        height="20"
        viewBox="0 0 20 20"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <path
          d="M1.75577 4.05495C1.91903 3.62801 2.39747 3.41426 2.8244 3.57752L4.36121 4.16518C4.78814 4.32844 5.0019 4.80688 4.83864 5.23381L3.24791 9.39375C3.08465 9.82068 2.60621 10.0344 2.17928 9.87118L0.642471 9.28351C0.215539 9.12026 0.00178741 8.64182 0.165043 8.21488L1.75577 4.05495Z"
          fill="green"
        />
        <path
          d="M3.74081 9.06138L5.05189 5.63277C5.14984 5.37661 5.43741 5.25266 5.70759 5.29971C7.29337 5.5759 9.09032 4.47109 10.8711 4.98027C12.8336 5.54139 15.4684 7.38981 16.6803 8.26454C15.4132 7.96426 14.2628 8.49171 13.846 8.79297L9.30455 8.53699C9.94649 8.65085 11.442 8.91016 12.2887 9.03649C13.347 9.19441 16.2311 9.31018 16.0491 10.4745C15.8671 11.6387 14.7793 11.6011 11.9834 11.4697C9.18752 11.3384 8.88607 12.3418 7.33215 12.0602C5.77824 11.7785 4.69463 10.5251 4.46331 10.1406C4.37871 9.9999 4.22653 9.8843 4.06418 9.79494C3.80156 9.65041 3.63375 9.34137 3.74081 9.06138Z"
          fill="green"
        />
        <path
          d="M9.58415 13.0414C9.2684 13.0167 8.96246 12.5866 8.84896 12.3746C9.21944 12.2507 9.78637 12.0764 10.2985 11.9909C10.7083 11.9224 11.39 11.9531 11.6796 11.977C11.6571 12.2359 11.6449 12.9018 11.7769 13.4942C11.0187 13.4711 10.6583 12.858 10.5729 12.5544C10.3749 12.727 9.8999 13.0661 9.58415 13.0414Z"
          fill="green"
        />
        <path
          fill-rule="evenodd"
          clip-rule="evenodd"
          d="M18.5383 15.5019C16.895 16.9373 14.3995 16.7689 12.964 15.1258C12.1784 14.2266 11.8732 13.072 12.0272 11.9757C12.993 11.9928 13.9691 12.0053 14.7323 11.8785C14.9182 11.8477 15.1041 11.8068 15.2826 11.7508C15.3489 12.0678 15.5117 12.386 15.658 12.6716C15.9898 13.3062 16.1109 13.6374 15.8487 13.8664C15.5915 14.0912 15.0869 13.9563 14.7476 13.5678C14.4082 13.1793 14.3423 12.6613 14.5996 12.4365L14.1833 11.9598C13.7566 12.3324 13.7004 12.9993 14.0015 13.5893L13.4821 14.0431L14.1067 14.758L14.6261 14.3042C15.1703 14.6817 15.8385 14.7157 16.2653 14.3431C16.9277 13.7642 16.5353 12.9976 16.2204 12.382C16.0033 11.967 15.8764 11.6817 15.8879 11.47C15.8967 11.4641 15.9055 11.458 15.9143 11.452C16.0629 11.3483 16.1915 11.2244 16.294 11.0808C16.5557 11.0576 16.8862 11.2059 17.1307 11.4858C17.4702 11.8743 17.536 12.3923 17.2787 12.6171L17.695 13.0939C18.1218 12.7212 18.1779 12.0543 17.8768 11.4644L18.3962 11.0106L17.7717 10.2956L17.2522 10.7494C17.0288 10.5943 16.7843 10.4971 16.5443 10.4625C16.5506 10.4221 16.5555 10.3809 16.5589 10.3387C16.5974 9.86082 16.3652 9.49948 16.0364 9.26625C15.7427 9.05789 15.3592 8.93785 14.9851 8.85448C14.8811 8.83115 14.7712 8.80968 14.6563 8.78933C16.1294 8.28422 17.8264 8.68264 18.9143 9.92781C20.3498 11.5709 20.1814 14.0665 18.5383 15.5019Z"
          fill="green"
        />
      </svg>
    );
  } else {
    return (
      <svg
        width="5vw"
        height="5vw"
        viewBox="0 0 27 28"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <path
          id="Vector"
          fill-rule="evenodd"
          clip-rule="evenodd"
          d="M6.84314 0H20.1568C21.7794 0 22.59 1.46028e-07 23.2452 0.228195C23.8629 0.447133 24.4219 0.805562 24.8786 1.27563C25.3353 1.74569 25.6775 2.31474 25.8785 2.93854C26.0997 3.61332 26.0997 4.4477 26.0997 6.11787V25.723C26.0997 26.9242 24.7207 27.5626 23.8486 26.7646C23.6039 26.5385 23.2829 26.4129 22.9498 26.4129C22.6166 26.4129 22.2957 26.5385 22.051 26.7646L21.3748 27.3834C20.9461 27.7798 20.3837 28 19.7999 28C19.216 28 18.6536 27.7798 18.2249 27.3834C17.7962 26.987 17.2338 26.7668 16.6499 26.7668C16.066 26.7668 15.5036 26.987 15.075 27.3834C14.6463 27.7798 14.0839 28 13.5 28C12.9161 28 12.3537 27.7798 11.925 27.3834C11.4963 26.987 10.9339 26.7668 10.3501 26.7668C9.76618 26.7668 9.20378 26.987 8.7751 27.3834C8.34642 27.7798 7.78401 28 7.20013 28C6.61625 28 6.05385 27.7798 5.62517 27.3834L4.94898 26.7646C4.70428 26.5385 4.38336 26.4129 4.0502 26.4129C3.71704 26.4129 3.39611 26.5385 3.15142 26.7646C2.27924 27.5626 0.900269 26.9242 0.900269 25.723V6.11787C0.900269 4.4477 0.900269 3.61192 1.12146 2.93994C1.54145 1.66176 2.51443 0.659386 3.75481 0.228195C4.40999 1.46028e-07 5.22057 0 6.84314 0ZM6.50015 6.64986C6.22167 6.64986 5.95461 6.76048 5.7577 6.95739C5.56079 7.15429 5.45017 7.42136 5.45017 7.69983C5.45017 7.9783 5.56079 8.24537 5.7577 8.44228C5.95461 8.63919 6.22167 8.74981 6.50015 8.74981H7.20013C7.4786 8.74981 7.74567 8.63919 7.94258 8.44228C8.13949 8.24537 8.25011 7.9783 8.25011 7.69983C8.25011 7.42136 8.13949 7.15429 7.94258 6.95739C7.74567 6.76048 7.4786 6.64986 7.20013 6.64986H6.50015ZM11.4 6.64986C11.1216 6.64986 10.8545 6.76048 10.6576 6.95739C10.4607 7.15429 10.3501 7.42136 10.3501 7.69983C10.3501 7.9783 10.4607 8.24537 10.6576 8.44228C10.8545 8.63919 11.1216 8.74981 11.4 8.74981H20.4998C20.7783 8.74981 21.0454 8.63919 21.2423 8.44228C21.4392 8.24537 21.5498 7.9783 21.5498 7.69983C21.5498 7.42136 21.4392 7.15429 21.2423 6.95739C21.0454 6.76048 20.7783 6.64986 20.4998 6.64986H11.4ZM6.50015 11.5497C6.22167 11.5497 5.95461 11.6604 5.7577 11.8573C5.56079 12.0542 5.45017 12.3213 5.45017 12.5997C5.45017 12.8782 5.56079 13.1453 5.7577 13.3422C5.95461 13.5391 6.22167 13.6497 6.50015 13.6497H7.20013C7.4786 13.6497 7.74567 13.5391 7.94258 13.3422C8.13949 13.1453 8.25011 12.8782 8.25011 12.5997C8.25011 12.3213 8.13949 12.0542 7.94258 11.8573C7.74567 11.6604 7.4786 11.5497 7.20013 11.5497H6.50015ZM11.4 11.5497C11.1216 11.5497 10.8545 11.6604 10.6576 11.8573C10.4607 12.0542 10.3501 12.3213 10.3501 12.5997C10.3501 12.8782 10.4607 13.1453 10.6576 13.3422C10.8545 13.5391 11.1216 13.6497 11.4 13.6497H20.4998C20.7783 13.6497 21.0454 13.5391 21.2423 13.3422C21.4392 13.1453 21.5498 12.8782 21.5498 12.5997C21.5498 12.3213 21.4392 12.0542 21.2423 11.8573C21.0454 11.6604 20.7783 11.5497 20.4998 11.5497H11.4ZM6.50015 16.4496C6.22167 16.4496 5.95461 16.5603 5.7577 16.7572C5.56079 16.9541 5.45017 17.2211 5.45017 17.4996C5.45017 17.7781 5.56079 18.0452 5.7577 18.2421C5.95461 18.439 6.22167 18.5496 6.50015 18.5496H7.20013C7.4786 18.5496 7.74567 18.439 7.94258 18.2421C8.13949 18.0452 8.25011 17.7781 8.25011 17.4996C8.25011 17.2211 8.13949 16.9541 7.94258 16.7572C7.74567 16.5603 7.4786 16.4496 7.20013 16.4496H6.50015ZM11.4 16.4496C11.1216 16.4496 10.8545 16.5603 10.6576 16.7572C10.4607 16.9541 10.3501 17.2211 10.3501 17.4996C10.3501 17.7781 10.4607 18.0452 10.6576 18.2421C10.8545 18.439 11.1216 18.5496 11.4 18.5496H20.4998C20.7783 18.5496 21.0454 18.439 21.2423 18.2421C21.4392 18.0452 21.5498 17.7781 21.5498 17.4996C21.5498 17.2211 21.4392 16.9541 21.2423 16.7572C21.0454 16.5603 20.7783 16.4496 20.4998 16.4496H11.4Z"
          fill="#151515"
        />
      </svg>
    );
  }
};
function BillDetails({ setFilterPop, data, filter }) {
  const { peer_id, showPopUp } = useContext(MainContext);
  var allData = [];
  var filteredData;
  let allNotEqual = !filter?.imPayee && !filter?.imDrawee && !filter?.imDrawer;
  if (filter?.imPayee) {
    filteredData = data.filter((d) => d.payee.peer_id === peer_id);
    allData.push(...filteredData);
  }
  if (filter?.imDrawee) {
    filteredData = data.filter((d) => d.drawee.peer_id === peer_id);
    allData.push(...filteredData);
  }
  if (filter?.imDrawer) {
    filteredData = data.filter((d) => d.drawer.peer_id === peer_id);
    allData.push(...filteredData);
  }
  if (allNotEqual) {
    allData.push(...data);
  }

  return (
    <>
      {allData?.map((items, i) => {
        let sign = signCalculation(peer_id, items);
        let name = namehandling(peer_id, items);

        return (
          <div
            key={i}
            onClick={() => {
              showPopUp(true, <SingleBillDetail item={items} />);
              setFilterPop && setFilterPop(false);
            }}
            className="home-container-bills-container"
          >
            <span className="icon-container">
              <span className="icon">
                {getIcon(
                  peer_id,
                  items?.drawee?.peer_id,
                  items?.payee?.peer_id,
                  {
                    accepted: items?.accepted,
                    endorsed: items?.endorsed,
                    requested_to_pay: items?.requested_to_pay,
                    requested_to_accept: items?.requested_to_accept,
                    payed: items?.payed,
                  }
                )}
              </span>
            </span>
            <div className="details">
              <span className="name">{name}</span>
              <span className="date">{items.date_of_issue}</span>
            </div>
            <div
              className={`currency-details ${
                items.amount_numbers > 99999 ? "currency-details-number" : ""
              }`}
              data-set={items.amount_numbers}
            >
              <div
                className={
                  sign === "+"
                    ? "amount"
                    : sign === "x"
                    ? "amount grey"
                    : sign === "-"
                    ? "amount red"
                    : "amount grey"
                }
              >
                <span>{sign === "x" ? "" : sign}</span>
                <span className="currency-details-amount">
                  {items.amount_numbers > 99999
                    ? items.amount_numbers?.toString()?.slice(0, 5) + "..."
                    : items.amount_numbers}
                </span>
              </div>
              <span className="currency">{items.currency_code}</span>
            </div>
          </div>
        );
      })}
    </>
  );
}

export default BillDetails;

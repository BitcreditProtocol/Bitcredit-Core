# Concepts

## Actions and Statuses by Roles

Here, we describe the `bill_actions`, `payment_actions` and `statuses`, which callers of the API get for a bill
depending on the bill state and their role in the bill.

### Roles

* Drawer - the issuer of the bill (can be the payee, or payer at the same time)
* Payer - the drawee of the bill, who the bill is issued against
* Holder - the current holder of the bill, either the bill payee, or the endorsee, the holder can also be a seller, or a recourser, depending on the action
* Contingent - participant in the guarantee chain
* Recoursee - the participant recoursed against
* Buyer - the user to offer to sell / sell to

### Bill Actions

Actions that can happen, depending on the role, which have an impact (i.e. a block) on the bill.
The full documentation of Actions and their validation for the different role can be found [here](https://github.com/BitcreditProtocol/cats/blob/main/Bitcredit-Core/bill_validation.md#bill-actions-validation).

* Payer Actions
    * Accept
    * RejectAcceptance
    * RejectPayment
* Holder Actions
    * RequestAcceptance
    * RequestToPay
    * OfferToSell
    * Sell
    * Endorse
    * Mint
    * RequestRecourseForAcceptance
    * RequestRecourseForPayment
    * Recourse
* Buyer Actions
    * RejectBuying
* Recoursee Actions
    * RejectPaymentForRecourse

### Payment Actions

Actions that can happen, depending on the role, which are related to payment

* **Pay** - the bill is currently waiting for a payment by the caller
    * contains the data to make the payment and metadata about the payment (e.g. what it's for - Recourse, Sell, Pay etc.)
        * `type` - e.g. Pay, Recourse, Sell (as an enum wrapper)
        * `receiver` - e.g. payee, seller, recourser
        * `time_of_request` - the timestamp the payment request was made
        * `currency` - the currency to pay in
        * `sum` - the sum to pay
        * `link_to_pay` - a generated link for the payment
        * `address_to_pay` - the BTC address to pay to
        * `mempool_link_for_address_to_pay` - 
        * `tx_id` - the BTC transaction ID
        * `in_mempool` - if the payment is in the mempool
        * `confirmations` -  the amount of confirmations the payment has
        * `payment_deadline` - the request deadline for the payment
* **Check Payment** - data for the receiver of current, or past payments
    * contains a list of the data (ordered by time of request descending, first is latest) to check and track current and past payments and metadata about the payments (e.g. what they are/were for - Recourse, Sell, Pay etc.)
        * `type` - e.g. Pay, Recourse, Sell (as an enum wrapper)
        * `sender` - e.g. payer, buyer, recoursee
        * `time_of_request` - the timestamp the payment request was made
        * `currency` - the currency to pay in
        * `sum` - the sum to pay
        * `link_to_pay` - a generated link for the payment
        * `address_to_pay` - the BTC address to pay to
        * `mempool_link_for_address_to_pay` - 
        * `tx_id` - the BTC transaction ID
        * `in_mempool` - if the payment is in the mempool
        * `confirmations` -  the amount of confirmations the payment has
        * `payment_deadline` - the request deadline for the payment
        * `private_descriptor_to_spend` - the BTC descriptor to spend the received funds
        * `status` - the status of the payment, e.g. Waiting, Paid, Rejected, Expired with the timestamps of the status

### Bill States

The `state` of the bill depends on several factors, roles and actually has several dimensions.

* Relevant for all roles at all times
    * Acceptance State - whether the bill is accepted, or not
        * requested to accept + deadline
        * accepted
        * rejected to accept
        * request to accept expired
    * Payment State - whether the bill is paid, or not
        * requested to pay + deadline
        * paid
        * rejected to pay
        * request to pay expired
* Relevant only for *current and past* participants of a recourse (recourser (=holder) and recoursee (=past holder))
    * Recourse States - whether the bill was recoursed between two participants, or not - can happen multiple times in the lifecycle of a bill, so this is a list of states (first in the list is latest)
        * requested to recourse + deadline
        * recoursed
        * rejected to pay recourse
        * request to recourse expired
* Relevant only for *current and past* participants of a sale (seller (=holder) and buyer)
    * Sell States - whether the bill was sold between two participants, or not - can happen multiple times in the lifecycle of a bill, so this is a list of states (first in the list is latest)
        * offered to sell + deadline
        * sold
        * rejected to buy
        * offer to sell expired
* Relevant only for *current* holders
    * Mint State - whether the bill was minted
        * requested to mint

### Permutations by Role

Based on the above, we can describe the different permutations by role and bill state as follows:

#### Payer

For the Payer role, there is no concept such as current and previous - the Payer stays the Payer.

* Bill Actions
    * RejectAcceptance (if bill was not accepted, or rejected/expired to accepted)
    * Accept (if bill was not accepted, or rejected/expired to accepted)
    * RejectPayment (if bill was requested to pay and not paid, or rejected/expired to pay)
* Payment Actions
    * Pay(Payment) (if bill was requested to pay and not paid, or rejected/expired to pay)
* States
    * Acceptance & Payment State

#### Holder

* Bill Actions
    * RequestAcceptance (if not requested to accept, accepted, or rejected/expired to accept)
    * RequestToPay (if not requested to pay, paid, or rejected/expired to pay)
    * OfferToSell
    * Sell (if an offer to sell was paid)
    * Endorse
    * Mint (if the bill is accepted)
* Payment Actions
    * CheckPayment(Payment) (if the bill was requested to pay)
* States
    * Acceptance & Payment State
    * Mint State (if the bill was requested to mint)

##### Addition for State: Bill can be Recoursed

If the bill can be recoursed, these actions are added to the above:

* Bill Actions
    * RequestRecourseForAcceptance (if rejected/expired to accept)
    * RequestRecourseForPayment (if rejected/expired to pay)
    * Recourse (if request to recourse was paid)

##### Addition for Holder as Seller, or Previous Seller

If the holder is currently a seller, or was a seller previously in the bill, these actions and states are added to the above:

* Payment Actions
    * CheckPayment(Sell)
* States
    * Sell States for the sales the buyer is/was involved in

##### Addition for Holder as Recourser, or Previous Recourser

If the holder is currently a recourser, or was a recourser previously in the bill, these actions and states are added to the above:

* Payment Actions
    * CheckPayment(Recourse)
* States
    * Recourse States for the recourses the recoursee is involved in

#### Drawer

For the Drawer role, there is no concept such as current and previous - the Drawer stays the Drawer.
The Drawer role by itself is not relevant in terms of actions, or states, only in combination of being Drawer and [Payer | Payee(Holder) | Recoursee], but these cases are handled in the corresponding roles.

* Bill Actions: None
* Payment Actions: None
* States
    * Acceptance & Payment State

#### Contingent

The Contingent role by itself is not relevant in terms of actions, or states.
Important for Contingent, especially for Payment Actions and States is the roles they had before (e.g. Holder, Buyer, Seller etc.)

* Bill Actions: None
* Payment Actions: None
* States
    * Acceptance & Payment State

#### Recoursee

##### State: Requested to Recourse (active)

* Bill Actions
    * RejectBuying
* Payment Actions
    * Pay(Sell)
* States
    * Acceptance & Payment State
    * Recourse States for the recourses the recoursee is involved in

##### State: Requested to Recourse (expired / rejected)

* Bill Actions: None
* Payment Actions: None
* States
    * Acceptance & Payment State
    * Recourse States for the recourses the recoursee is involved in

##### State: Recoursed

* Bill Actions: Holder Bill Actions
* Payment Actions: Holder Payment Actions
* States
    * Holder States
    * Recourse States for the recourses the recoursee is involved in

#### Buyer

##### State: Offered To Sell (active)

* Bill Actions
    * RejectBuying
* Payment Actions
    * Pay(Sell)
* States
    * Acceptance & Payment State
    * Sell States for the sales the buyer is/was involved in

##### State: Offered To Sell (expired / rejected)

* Bill Actions: None
* Payment Actions: None
* States
    * Acceptance & Payment State
    * Sell States for the sales the buyer is/was involved in

##### State: Sold 

* Bill Actions: Holder Bill Actions
* Payment Actions: Holder Payment Actions
* States
    * Holder States
    * Sell States for the sales the buyer is/was involved in

#### Special Cases

Here, we describe special cases, such as when Payer == Holder, Payer == Buyer etc.

##### Payer == Holder

We simply add together the states and actions of the Payer and Holder roles.

##### Payer == Buyer

We simply add together the states and actions of the Payer and Buyer roles.

### Examples

This is a non-exhaustive set of examples. Mostly for demonstrating specific cases up for discussion with the same format

#### Bill just issued (1 block), Drawer == Payer

##### Role: Holder

* Bill Actions
    * RequestAcceptance
    * RequestToPay
    * OfferToSell
    * Endorse
* Payment Actions: None
* States
    * Acceptance
        * requested to accept = false
        * accepted = false
        * rejected to accept = false
        * request to accept expired = false
    * Payment
        * requested to pay = false
        * paid = false
        * rejected to pay = false
        * request to pay expired = false

##### Role: Payer

* Bill Actions
    * Accept
    * RejectAcceptance
* Payment Actions: None
* States
    * Acceptance
        * requested to accept = false
        * accepted = false
        * rejected to accept = false
        * request to accept expired = false
    * Payment
        * requested to pay = false
        * paid = false
        * rejected to pay = false
        * request to pay expired = false

#### Bill offered to sell (2 blocks), Drawer == Payer, Buyer != Payer, not rejected, or expired

##### Role: Holder

* Bill Actions
    * Sell (if we detect the payment arrived)
* Payment Actions
    * CheckPayment(Sell)
        * sender = Buyer
        * ...
* States
    * Acceptance
        * requested to accept = false
        * accepted = false
        * rejected to accept = false
        * request to accept expired = false
    * Payment
        * requested to pay = false
        * paid = false
        * rejected to pay = false
        * request to pay expired = false
    * Sell States for the current OfferToSell
        * offered to sell = true
        * sold = false
        * rejected to buy = false
        * offer to sell expired = false

##### Role: Buyer

* Bill Actions
    * RejectBuying
* Payment Actions
    * Pay(Sell)
        * receiver = Holder
        * ...
* States
    * Acceptance
        * requested to accept = false
        * accepted = false
        * rejected to accept = false
        * request to accept expired = false
    * Payment
        * requested to pay = false
        * paid = false
        * rejected to pay = false
        * request to pay expired = false
    * Sell States for the current OfferToSell
        * offered to sell = true
        * sold = false
        * rejected to buy = false
        * offer to sell expired = false

##### Role: Payer

* Bill Actions: None
* Payment Actions: None
* States
    * Acceptance
        * requested to accept = false
        * accepted = false
        * rejected to accept = false
        * request to accept expired = false
    * Payment
        * requested to pay = false
        * paid = false
        * rejected to pay = false
        * request to pay expired = false

#### Bill sold (3 blocks), Drawer == Payer, Buyer != Payer

##### Role: Holder (=previous Buyer)

* Bill Actions
    * RequestAcceptance
    * RequestToPay
    * OfferToSell
    * Endorse
* Payment Actions: None
* States
    * Acceptance
        * requested to accept = false
        * accepted = false
        * rejected to accept = false
        * request to accept expired = false
    * Payment
        * requested to pay = false
        * paid = false
        * rejected to pay = false
        * request to pay expired = false
    * Sell States for the current OfferToSell
        * offered to sell = true
        * sold = true
        * rejected to buy = false
        * offer to sell expired = false

##### Role: Seller (=previous Holder)

* Bill Actions: None
* Payment Actions
    * CheckPayment(Sell) - this is a past payment
        * sender = Buyer
        * ...
* States
    * Acceptance
        * requested to accept = false
        * accepted = false
        * rejected to accept = false
        * request to accept expired = false
    * Payment
        * requested to pay = false
        * paid = false
        * rejected to pay = false
        * request to pay expired = false
    * Sell States for the current OfferToSell
        * offered to sell = true
        * sold = true
        * rejected to buy = false
        * offer to sell expired = false

##### Role: Payer

* Bill Actions
    * Accept
    * RejectAcceptance
* Payment Actions: None
* States
    * Acceptance
        * requested to accept = false
        * accepted = false
        * rejected to accept = false
        * request to accept expired = false
    * Payment
        * requested to pay = false
        * paid = false
        * rejected to pay = false
        * request to pay expired = false


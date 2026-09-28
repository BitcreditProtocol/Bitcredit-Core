// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'bill.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$BillAcceptStateFfi {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillAcceptStateFfi);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'BillAcceptStateFfi()';
}


}

/// @nodoc
class $BillAcceptStateFfiCopyWith<$Res>  {
$BillAcceptStateFfiCopyWith(BillAcceptStateFfi _, $Res Function(BillAcceptStateFfi) __);
}


/// Adds pattern-matching-related methods to [BillAcceptStateFfi].
extension BillAcceptStateFfiPatterns on BillAcceptStateFfi {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( BillAcceptStateFfi_None value)?  none,TResult Function( BillAcceptStateFfi_Requested value)?  requested,TResult Function( BillAcceptStateFfi_Accepted value)?  accepted,TResult Function( BillAcceptStateFfi_Expired value)?  expired,TResult Function( BillAcceptStateFfi_Rejected value)?  rejected,required TResult orElse(),}){
final _that = this;
switch (_that) {
case BillAcceptStateFfi_None() when none != null:
return none(_that);case BillAcceptStateFfi_Requested() when requested != null:
return requested(_that);case BillAcceptStateFfi_Accepted() when accepted != null:
return accepted(_that);case BillAcceptStateFfi_Expired() when expired != null:
return expired(_that);case BillAcceptStateFfi_Rejected() when rejected != null:
return rejected(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( BillAcceptStateFfi_None value)  none,required TResult Function( BillAcceptStateFfi_Requested value)  requested,required TResult Function( BillAcceptStateFfi_Accepted value)  accepted,required TResult Function( BillAcceptStateFfi_Expired value)  expired,required TResult Function( BillAcceptStateFfi_Rejected value)  rejected,}){
final _that = this;
switch (_that) {
case BillAcceptStateFfi_None():
return none(_that);case BillAcceptStateFfi_Requested():
return requested(_that);case BillAcceptStateFfi_Accepted():
return accepted(_that);case BillAcceptStateFfi_Expired():
return expired(_that);case BillAcceptStateFfi_Rejected():
return rejected(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( BillAcceptStateFfi_None value)?  none,TResult? Function( BillAcceptStateFfi_Requested value)?  requested,TResult? Function( BillAcceptStateFfi_Accepted value)?  accepted,TResult? Function( BillAcceptStateFfi_Expired value)?  expired,TResult? Function( BillAcceptStateFfi_Rejected value)?  rejected,}){
final _that = this;
switch (_that) {
case BillAcceptStateFfi_None() when none != null:
return none(_that);case BillAcceptStateFfi_Requested() when requested != null:
return requested(_that);case BillAcceptStateFfi_Accepted() when accepted != null:
return accepted(_that);case BillAcceptStateFfi_Expired() when expired != null:
return expired(_that);case BillAcceptStateFfi_Rejected() when rejected != null:
return rejected(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function()?  none,TResult Function( BigInt field0)?  requested,TResult Function( BigInt field0)?  accepted,TResult Function( BigInt field0)?  expired,TResult Function( BigInt field0)?  rejected,required TResult orElse(),}) {final _that = this;
switch (_that) {
case BillAcceptStateFfi_None() when none != null:
return none();case BillAcceptStateFfi_Requested() when requested != null:
return requested(_that.field0);case BillAcceptStateFfi_Accepted() when accepted != null:
return accepted(_that.field0);case BillAcceptStateFfi_Expired() when expired != null:
return expired(_that.field0);case BillAcceptStateFfi_Rejected() when rejected != null:
return rejected(_that.field0);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function()  none,required TResult Function( BigInt field0)  requested,required TResult Function( BigInt field0)  accepted,required TResult Function( BigInt field0)  expired,required TResult Function( BigInt field0)  rejected,}) {final _that = this;
switch (_that) {
case BillAcceptStateFfi_None():
return none();case BillAcceptStateFfi_Requested():
return requested(_that.field0);case BillAcceptStateFfi_Accepted():
return accepted(_that.field0);case BillAcceptStateFfi_Expired():
return expired(_that.field0);case BillAcceptStateFfi_Rejected():
return rejected(_that.field0);}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function()?  none,TResult? Function( BigInt field0)?  requested,TResult? Function( BigInt field0)?  accepted,TResult? Function( BigInt field0)?  expired,TResult? Function( BigInt field0)?  rejected,}) {final _that = this;
switch (_that) {
case BillAcceptStateFfi_None() when none != null:
return none();case BillAcceptStateFfi_Requested() when requested != null:
return requested(_that.field0);case BillAcceptStateFfi_Accepted() when accepted != null:
return accepted(_that.field0);case BillAcceptStateFfi_Expired() when expired != null:
return expired(_that.field0);case BillAcceptStateFfi_Rejected() when rejected != null:
return rejected(_that.field0);case _:
  return null;

}
}

}

/// @nodoc


class BillAcceptStateFfi_None extends BillAcceptStateFfi {
  const BillAcceptStateFfi_None(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillAcceptStateFfi_None);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'BillAcceptStateFfi.none()';
}


}




/// @nodoc


class BillAcceptStateFfi_Requested extends BillAcceptStateFfi {
  const BillAcceptStateFfi_Requested(this.field0): super._();
  

 final  BigInt field0;

/// Create a copy of BillAcceptStateFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BillAcceptStateFfi_RequestedCopyWith<BillAcceptStateFfi_Requested> get copyWith => _$BillAcceptStateFfi_RequestedCopyWithImpl<BillAcceptStateFfi_Requested>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillAcceptStateFfi_Requested&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'BillAcceptStateFfi.requested(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $BillAcceptStateFfi_RequestedCopyWith<$Res> implements $BillAcceptStateFfiCopyWith<$Res> {
  factory $BillAcceptStateFfi_RequestedCopyWith(BillAcceptStateFfi_Requested value, $Res Function(BillAcceptStateFfi_Requested) _then) = _$BillAcceptStateFfi_RequestedCopyWithImpl;
@useResult
$Res call({
 BigInt field0
});




}
/// @nodoc
class _$BillAcceptStateFfi_RequestedCopyWithImpl<$Res>
    implements $BillAcceptStateFfi_RequestedCopyWith<$Res> {
  _$BillAcceptStateFfi_RequestedCopyWithImpl(this._self, this._then);

  final BillAcceptStateFfi_Requested _self;
  final $Res Function(BillAcceptStateFfi_Requested) _then;

/// Create a copy of BillAcceptStateFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(BillAcceptStateFfi_Requested(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class BillAcceptStateFfi_Accepted extends BillAcceptStateFfi {
  const BillAcceptStateFfi_Accepted(this.field0): super._();
  

 final  BigInt field0;

/// Create a copy of BillAcceptStateFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BillAcceptStateFfi_AcceptedCopyWith<BillAcceptStateFfi_Accepted> get copyWith => _$BillAcceptStateFfi_AcceptedCopyWithImpl<BillAcceptStateFfi_Accepted>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillAcceptStateFfi_Accepted&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'BillAcceptStateFfi.accepted(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $BillAcceptStateFfi_AcceptedCopyWith<$Res> implements $BillAcceptStateFfiCopyWith<$Res> {
  factory $BillAcceptStateFfi_AcceptedCopyWith(BillAcceptStateFfi_Accepted value, $Res Function(BillAcceptStateFfi_Accepted) _then) = _$BillAcceptStateFfi_AcceptedCopyWithImpl;
@useResult
$Res call({
 BigInt field0
});




}
/// @nodoc
class _$BillAcceptStateFfi_AcceptedCopyWithImpl<$Res>
    implements $BillAcceptStateFfi_AcceptedCopyWith<$Res> {
  _$BillAcceptStateFfi_AcceptedCopyWithImpl(this._self, this._then);

  final BillAcceptStateFfi_Accepted _self;
  final $Res Function(BillAcceptStateFfi_Accepted) _then;

/// Create a copy of BillAcceptStateFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(BillAcceptStateFfi_Accepted(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class BillAcceptStateFfi_Expired extends BillAcceptStateFfi {
  const BillAcceptStateFfi_Expired(this.field0): super._();
  

 final  BigInt field0;

/// Create a copy of BillAcceptStateFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BillAcceptStateFfi_ExpiredCopyWith<BillAcceptStateFfi_Expired> get copyWith => _$BillAcceptStateFfi_ExpiredCopyWithImpl<BillAcceptStateFfi_Expired>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillAcceptStateFfi_Expired&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'BillAcceptStateFfi.expired(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $BillAcceptStateFfi_ExpiredCopyWith<$Res> implements $BillAcceptStateFfiCopyWith<$Res> {
  factory $BillAcceptStateFfi_ExpiredCopyWith(BillAcceptStateFfi_Expired value, $Res Function(BillAcceptStateFfi_Expired) _then) = _$BillAcceptStateFfi_ExpiredCopyWithImpl;
@useResult
$Res call({
 BigInt field0
});




}
/// @nodoc
class _$BillAcceptStateFfi_ExpiredCopyWithImpl<$Res>
    implements $BillAcceptStateFfi_ExpiredCopyWith<$Res> {
  _$BillAcceptStateFfi_ExpiredCopyWithImpl(this._self, this._then);

  final BillAcceptStateFfi_Expired _self;
  final $Res Function(BillAcceptStateFfi_Expired) _then;

/// Create a copy of BillAcceptStateFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(BillAcceptStateFfi_Expired(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class BillAcceptStateFfi_Rejected extends BillAcceptStateFfi {
  const BillAcceptStateFfi_Rejected(this.field0): super._();
  

 final  BigInt field0;

/// Create a copy of BillAcceptStateFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BillAcceptStateFfi_RejectedCopyWith<BillAcceptStateFfi_Rejected> get copyWith => _$BillAcceptStateFfi_RejectedCopyWithImpl<BillAcceptStateFfi_Rejected>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillAcceptStateFfi_Rejected&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'BillAcceptStateFfi.rejected(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $BillAcceptStateFfi_RejectedCopyWith<$Res> implements $BillAcceptStateFfiCopyWith<$Res> {
  factory $BillAcceptStateFfi_RejectedCopyWith(BillAcceptStateFfi_Rejected value, $Res Function(BillAcceptStateFfi_Rejected) _then) = _$BillAcceptStateFfi_RejectedCopyWithImpl;
@useResult
$Res call({
 BigInt field0
});




}
/// @nodoc
class _$BillAcceptStateFfi_RejectedCopyWithImpl<$Res>
    implements $BillAcceptStateFfi_RejectedCopyWith<$Res> {
  _$BillAcceptStateFfi_RejectedCopyWithImpl(this._self, this._then);

  final BillAcceptStateFfi_Rejected _self;
  final $Res Function(BillAcceptStateFfi_Rejected) _then;

/// Create a copy of BillAcceptStateFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(BillAcceptStateFfi_Rejected(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc
mixin _$BillCallerPaymentActionFfi {

 BillCallerPaymentFfi get field0;
/// Create a copy of BillCallerPaymentActionFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BillCallerPaymentActionFfiCopyWith<BillCallerPaymentActionFfi> get copyWith => _$BillCallerPaymentActionFfiCopyWithImpl<BillCallerPaymentActionFfi>(this as BillCallerPaymentActionFfi, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillCallerPaymentActionFfi&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'BillCallerPaymentActionFfi(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $BillCallerPaymentActionFfiCopyWith<$Res>  {
  factory $BillCallerPaymentActionFfiCopyWith(BillCallerPaymentActionFfi value, $Res Function(BillCallerPaymentActionFfi) _then) = _$BillCallerPaymentActionFfiCopyWithImpl;
@useResult
$Res call({
 BillCallerPaymentFfi field0
});


$BillCallerPaymentFfiCopyWith<$Res> get field0;

}
/// @nodoc
class _$BillCallerPaymentActionFfiCopyWithImpl<$Res>
    implements $BillCallerPaymentActionFfiCopyWith<$Res> {
  _$BillCallerPaymentActionFfiCopyWithImpl(this._self, this._then);

  final BillCallerPaymentActionFfi _self;
  final $Res Function(BillCallerPaymentActionFfi) _then;

/// Create a copy of BillCallerPaymentActionFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') @override $Res call({Object? field0 = null,}) {
  return _then(_self.copyWith(
field0: null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BillCallerPaymentFfi,
  ));
}
/// Create a copy of BillCallerPaymentActionFfi
/// with the given fields replaced by the non-null parameter values.
@override
@pragma('vm:prefer-inline')
$BillCallerPaymentFfiCopyWith<$Res> get field0 {
  
  return $BillCallerPaymentFfiCopyWith<$Res>(_self.field0, (value) {
    return _then(_self.copyWith(field0: value));
  });
}
}


/// Adds pattern-matching-related methods to [BillCallerPaymentActionFfi].
extension BillCallerPaymentActionFfiPatterns on BillCallerPaymentActionFfi {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( BillCallerPaymentActionFfi_Pay value)?  pay,TResult Function( BillCallerPaymentActionFfi_CheckPayment value)?  checkPayment,required TResult orElse(),}){
final _that = this;
switch (_that) {
case BillCallerPaymentActionFfi_Pay() when pay != null:
return pay(_that);case BillCallerPaymentActionFfi_CheckPayment() when checkPayment != null:
return checkPayment(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( BillCallerPaymentActionFfi_Pay value)  pay,required TResult Function( BillCallerPaymentActionFfi_CheckPayment value)  checkPayment,}){
final _that = this;
switch (_that) {
case BillCallerPaymentActionFfi_Pay():
return pay(_that);case BillCallerPaymentActionFfi_CheckPayment():
return checkPayment(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( BillCallerPaymentActionFfi_Pay value)?  pay,TResult? Function( BillCallerPaymentActionFfi_CheckPayment value)?  checkPayment,}){
final _that = this;
switch (_that) {
case BillCallerPaymentActionFfi_Pay() when pay != null:
return pay(_that);case BillCallerPaymentActionFfi_CheckPayment() when checkPayment != null:
return checkPayment(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( BillCallerPaymentFfi field0)?  pay,TResult Function( BillCallerPaymentFfi field0)?  checkPayment,required TResult orElse(),}) {final _that = this;
switch (_that) {
case BillCallerPaymentActionFfi_Pay() when pay != null:
return pay(_that.field0);case BillCallerPaymentActionFfi_CheckPayment() when checkPayment != null:
return checkPayment(_that.field0);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( BillCallerPaymentFfi field0)  pay,required TResult Function( BillCallerPaymentFfi field0)  checkPayment,}) {final _that = this;
switch (_that) {
case BillCallerPaymentActionFfi_Pay():
return pay(_that.field0);case BillCallerPaymentActionFfi_CheckPayment():
return checkPayment(_that.field0);}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( BillCallerPaymentFfi field0)?  pay,TResult? Function( BillCallerPaymentFfi field0)?  checkPayment,}) {final _that = this;
switch (_that) {
case BillCallerPaymentActionFfi_Pay() when pay != null:
return pay(_that.field0);case BillCallerPaymentActionFfi_CheckPayment() when checkPayment != null:
return checkPayment(_that.field0);case _:
  return null;

}
}

}

/// @nodoc


class BillCallerPaymentActionFfi_Pay extends BillCallerPaymentActionFfi {
  const BillCallerPaymentActionFfi_Pay(this.field0): super._();
  

@override final  BillCallerPaymentFfi field0;

/// Create a copy of BillCallerPaymentActionFfi
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BillCallerPaymentActionFfi_PayCopyWith<BillCallerPaymentActionFfi_Pay> get copyWith => _$BillCallerPaymentActionFfi_PayCopyWithImpl<BillCallerPaymentActionFfi_Pay>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillCallerPaymentActionFfi_Pay&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'BillCallerPaymentActionFfi.pay(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $BillCallerPaymentActionFfi_PayCopyWith<$Res> implements $BillCallerPaymentActionFfiCopyWith<$Res> {
  factory $BillCallerPaymentActionFfi_PayCopyWith(BillCallerPaymentActionFfi_Pay value, $Res Function(BillCallerPaymentActionFfi_Pay) _then) = _$BillCallerPaymentActionFfi_PayCopyWithImpl;
@override @useResult
$Res call({
 BillCallerPaymentFfi field0
});


@override $BillCallerPaymentFfiCopyWith<$Res> get field0;

}
/// @nodoc
class _$BillCallerPaymentActionFfi_PayCopyWithImpl<$Res>
    implements $BillCallerPaymentActionFfi_PayCopyWith<$Res> {
  _$BillCallerPaymentActionFfi_PayCopyWithImpl(this._self, this._then);

  final BillCallerPaymentActionFfi_Pay _self;
  final $Res Function(BillCallerPaymentActionFfi_Pay) _then;

/// Create a copy of BillCallerPaymentActionFfi
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(BillCallerPaymentActionFfi_Pay(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BillCallerPaymentFfi,
  ));
}

/// Create a copy of BillCallerPaymentActionFfi
/// with the given fields replaced by the non-null parameter values.
@override
@pragma('vm:prefer-inline')
$BillCallerPaymentFfiCopyWith<$Res> get field0 {
  
  return $BillCallerPaymentFfiCopyWith<$Res>(_self.field0, (value) {
    return _then(_self.copyWith(field0: value));
  });
}
}

/// @nodoc


class BillCallerPaymentActionFfi_CheckPayment extends BillCallerPaymentActionFfi {
  const BillCallerPaymentActionFfi_CheckPayment(this.field0): super._();
  

@override final  BillCallerPaymentFfi field0;

/// Create a copy of BillCallerPaymentActionFfi
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BillCallerPaymentActionFfi_CheckPaymentCopyWith<BillCallerPaymentActionFfi_CheckPayment> get copyWith => _$BillCallerPaymentActionFfi_CheckPaymentCopyWithImpl<BillCallerPaymentActionFfi_CheckPayment>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillCallerPaymentActionFfi_CheckPayment&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'BillCallerPaymentActionFfi.checkPayment(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $BillCallerPaymentActionFfi_CheckPaymentCopyWith<$Res> implements $BillCallerPaymentActionFfiCopyWith<$Res> {
  factory $BillCallerPaymentActionFfi_CheckPaymentCopyWith(BillCallerPaymentActionFfi_CheckPayment value, $Res Function(BillCallerPaymentActionFfi_CheckPayment) _then) = _$BillCallerPaymentActionFfi_CheckPaymentCopyWithImpl;
@override @useResult
$Res call({
 BillCallerPaymentFfi field0
});


@override $BillCallerPaymentFfiCopyWith<$Res> get field0;

}
/// @nodoc
class _$BillCallerPaymentActionFfi_CheckPaymentCopyWithImpl<$Res>
    implements $BillCallerPaymentActionFfi_CheckPaymentCopyWith<$Res> {
  _$BillCallerPaymentActionFfi_CheckPaymentCopyWithImpl(this._self, this._then);

  final BillCallerPaymentActionFfi_CheckPayment _self;
  final $Res Function(BillCallerPaymentActionFfi_CheckPayment) _then;

/// Create a copy of BillCallerPaymentActionFfi
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(BillCallerPaymentActionFfi_CheckPayment(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BillCallerPaymentFfi,
  ));
}

/// Create a copy of BillCallerPaymentActionFfi
/// with the given fields replaced by the non-null parameter values.
@override
@pragma('vm:prefer-inline')
$BillCallerPaymentFfiCopyWith<$Res> get field0 {
  
  return $BillCallerPaymentFfiCopyWith<$Res>(_self.field0, (value) {
    return _then(_self.copyWith(field0: value));
  });
}
}

/// @nodoc
mixin _$BillCallerPaymentFfi {

 BillCallerPaymentStateFfi get state;
/// Create a copy of BillCallerPaymentFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BillCallerPaymentFfiCopyWith<BillCallerPaymentFfi> get copyWith => _$BillCallerPaymentFfiCopyWithImpl<BillCallerPaymentFfi>(this as BillCallerPaymentFfi, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillCallerPaymentFfi&&(identical(other.state, state) || other.state == state));
}


@override
int get hashCode => Object.hash(runtimeType,state);

@override
String toString() {
  return 'BillCallerPaymentFfi(state: $state)';
}


}

/// @nodoc
abstract mixin class $BillCallerPaymentFfiCopyWith<$Res>  {
  factory $BillCallerPaymentFfiCopyWith(BillCallerPaymentFfi value, $Res Function(BillCallerPaymentFfi) _then) = _$BillCallerPaymentFfiCopyWithImpl;
@useResult
$Res call({
 BillCallerPaymentStateFfi state
});




}
/// @nodoc
class _$BillCallerPaymentFfiCopyWithImpl<$Res>
    implements $BillCallerPaymentFfiCopyWith<$Res> {
  _$BillCallerPaymentFfiCopyWithImpl(this._self, this._then);

  final BillCallerPaymentFfi _self;
  final $Res Function(BillCallerPaymentFfi) _then;

/// Create a copy of BillCallerPaymentFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') @override $Res call({Object? state = null,}) {
  return _then(_self.copyWith(
state: null == state ? _self.state : state // ignore: cast_nullable_to_non_nullable
as BillCallerPaymentStateFfi,
  ));
}

}


/// Adds pattern-matching-related methods to [BillCallerPaymentFfi].
extension BillCallerPaymentFfiPatterns on BillCallerPaymentFfi {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( BillCallerPaymentFfi_Sell value)?  sell,TResult Function( BillCallerPaymentFfi_Payment value)?  payment,TResult Function( BillCallerPaymentFfi_Recourse value)?  recourse,required TResult orElse(),}){
final _that = this;
switch (_that) {
case BillCallerPaymentFfi_Sell() when sell != null:
return sell(_that);case BillCallerPaymentFfi_Payment() when payment != null:
return payment(_that);case BillCallerPaymentFfi_Recourse() when recourse != null:
return recourse(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( BillCallerPaymentFfi_Sell value)  sell,required TResult Function( BillCallerPaymentFfi_Payment value)  payment,required TResult Function( BillCallerPaymentFfi_Recourse value)  recourse,}){
final _that = this;
switch (_that) {
case BillCallerPaymentFfi_Sell():
return sell(_that);case BillCallerPaymentFfi_Payment():
return payment(_that);case BillCallerPaymentFfi_Recourse():
return recourse(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( BillCallerPaymentFfi_Sell value)?  sell,TResult? Function( BillCallerPaymentFfi_Payment value)?  payment,TResult? Function( BillCallerPaymentFfi_Recourse value)?  recourse,}){
final _that = this;
switch (_that) {
case BillCallerPaymentFfi_Sell() when sell != null:
return sell(_that);case BillCallerPaymentFfi_Payment() when payment != null:
return payment(_that);case BillCallerPaymentFfi_Recourse() when recourse != null:
return recourse(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( BillParticipantFfi buyer,  BillParticipantFfi seller,  BillCallerPaymentStateFfi state)?  sell,TResult Function( BillIdentParticipantFfi payer,  BillParticipantFfi payee,  BillCallerPaymentStateFfi state)?  payment,TResult Function( BillParticipantFfi recourser,  BillIdentParticipantFfi recoursee,  BillCallerPaymentStateFfi state)?  recourse,required TResult orElse(),}) {final _that = this;
switch (_that) {
case BillCallerPaymentFfi_Sell() when sell != null:
return sell(_that.buyer,_that.seller,_that.state);case BillCallerPaymentFfi_Payment() when payment != null:
return payment(_that.payer,_that.payee,_that.state);case BillCallerPaymentFfi_Recourse() when recourse != null:
return recourse(_that.recourser,_that.recoursee,_that.state);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( BillParticipantFfi buyer,  BillParticipantFfi seller,  BillCallerPaymentStateFfi state)  sell,required TResult Function( BillIdentParticipantFfi payer,  BillParticipantFfi payee,  BillCallerPaymentStateFfi state)  payment,required TResult Function( BillParticipantFfi recourser,  BillIdentParticipantFfi recoursee,  BillCallerPaymentStateFfi state)  recourse,}) {final _that = this;
switch (_that) {
case BillCallerPaymentFfi_Sell():
return sell(_that.buyer,_that.seller,_that.state);case BillCallerPaymentFfi_Payment():
return payment(_that.payer,_that.payee,_that.state);case BillCallerPaymentFfi_Recourse():
return recourse(_that.recourser,_that.recoursee,_that.state);}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( BillParticipantFfi buyer,  BillParticipantFfi seller,  BillCallerPaymentStateFfi state)?  sell,TResult? Function( BillIdentParticipantFfi payer,  BillParticipantFfi payee,  BillCallerPaymentStateFfi state)?  payment,TResult? Function( BillParticipantFfi recourser,  BillIdentParticipantFfi recoursee,  BillCallerPaymentStateFfi state)?  recourse,}) {final _that = this;
switch (_that) {
case BillCallerPaymentFfi_Sell() when sell != null:
return sell(_that.buyer,_that.seller,_that.state);case BillCallerPaymentFfi_Payment() when payment != null:
return payment(_that.payer,_that.payee,_that.state);case BillCallerPaymentFfi_Recourse() when recourse != null:
return recourse(_that.recourser,_that.recoursee,_that.state);case _:
  return null;

}
}

}

/// @nodoc


class BillCallerPaymentFfi_Sell extends BillCallerPaymentFfi {
  const BillCallerPaymentFfi_Sell({required this.buyer, required this.seller, required this.state}): super._();
  

 final  BillParticipantFfi buyer;
 final  BillParticipantFfi seller;
@override final  BillCallerPaymentStateFfi state;

/// Create a copy of BillCallerPaymentFfi
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BillCallerPaymentFfi_SellCopyWith<BillCallerPaymentFfi_Sell> get copyWith => _$BillCallerPaymentFfi_SellCopyWithImpl<BillCallerPaymentFfi_Sell>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillCallerPaymentFfi_Sell&&(identical(other.buyer, buyer) || other.buyer == buyer)&&(identical(other.seller, seller) || other.seller == seller)&&(identical(other.state, state) || other.state == state));
}


@override
int get hashCode => Object.hash(runtimeType,buyer,seller,state);

@override
String toString() {
  return 'BillCallerPaymentFfi.sell(buyer: $buyer, seller: $seller, state: $state)';
}


}

/// @nodoc
abstract mixin class $BillCallerPaymentFfi_SellCopyWith<$Res> implements $BillCallerPaymentFfiCopyWith<$Res> {
  factory $BillCallerPaymentFfi_SellCopyWith(BillCallerPaymentFfi_Sell value, $Res Function(BillCallerPaymentFfi_Sell) _then) = _$BillCallerPaymentFfi_SellCopyWithImpl;
@override @useResult
$Res call({
 BillParticipantFfi buyer, BillParticipantFfi seller, BillCallerPaymentStateFfi state
});


$BillParticipantFfiCopyWith<$Res> get buyer;$BillParticipantFfiCopyWith<$Res> get seller;

}
/// @nodoc
class _$BillCallerPaymentFfi_SellCopyWithImpl<$Res>
    implements $BillCallerPaymentFfi_SellCopyWith<$Res> {
  _$BillCallerPaymentFfi_SellCopyWithImpl(this._self, this._then);

  final BillCallerPaymentFfi_Sell _self;
  final $Res Function(BillCallerPaymentFfi_Sell) _then;

/// Create a copy of BillCallerPaymentFfi
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? buyer = null,Object? seller = null,Object? state = null,}) {
  return _then(BillCallerPaymentFfi_Sell(
buyer: null == buyer ? _self.buyer : buyer // ignore: cast_nullable_to_non_nullable
as BillParticipantFfi,seller: null == seller ? _self.seller : seller // ignore: cast_nullable_to_non_nullable
as BillParticipantFfi,state: null == state ? _self.state : state // ignore: cast_nullable_to_non_nullable
as BillCallerPaymentStateFfi,
  ));
}

/// Create a copy of BillCallerPaymentFfi
/// with the given fields replaced by the non-null parameter values.
@override
@pragma('vm:prefer-inline')
$BillParticipantFfiCopyWith<$Res> get buyer {
  
  return $BillParticipantFfiCopyWith<$Res>(_self.buyer, (value) {
    return _then(_self.copyWith(buyer: value));
  });
}/// Create a copy of BillCallerPaymentFfi
/// with the given fields replaced by the non-null parameter values.
@override
@pragma('vm:prefer-inline')
$BillParticipantFfiCopyWith<$Res> get seller {
  
  return $BillParticipantFfiCopyWith<$Res>(_self.seller, (value) {
    return _then(_self.copyWith(seller: value));
  });
}
}

/// @nodoc


class BillCallerPaymentFfi_Payment extends BillCallerPaymentFfi {
  const BillCallerPaymentFfi_Payment({required this.payer, required this.payee, required this.state}): super._();
  

 final  BillIdentParticipantFfi payer;
 final  BillParticipantFfi payee;
@override final  BillCallerPaymentStateFfi state;

/// Create a copy of BillCallerPaymentFfi
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BillCallerPaymentFfi_PaymentCopyWith<BillCallerPaymentFfi_Payment> get copyWith => _$BillCallerPaymentFfi_PaymentCopyWithImpl<BillCallerPaymentFfi_Payment>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillCallerPaymentFfi_Payment&&(identical(other.payer, payer) || other.payer == payer)&&(identical(other.payee, payee) || other.payee == payee)&&(identical(other.state, state) || other.state == state));
}


@override
int get hashCode => Object.hash(runtimeType,payer,payee,state);

@override
String toString() {
  return 'BillCallerPaymentFfi.payment(payer: $payer, payee: $payee, state: $state)';
}


}

/// @nodoc
abstract mixin class $BillCallerPaymentFfi_PaymentCopyWith<$Res> implements $BillCallerPaymentFfiCopyWith<$Res> {
  factory $BillCallerPaymentFfi_PaymentCopyWith(BillCallerPaymentFfi_Payment value, $Res Function(BillCallerPaymentFfi_Payment) _then) = _$BillCallerPaymentFfi_PaymentCopyWithImpl;
@override @useResult
$Res call({
 BillIdentParticipantFfi payer, BillParticipantFfi payee, BillCallerPaymentStateFfi state
});


$BillParticipantFfiCopyWith<$Res> get payee;

}
/// @nodoc
class _$BillCallerPaymentFfi_PaymentCopyWithImpl<$Res>
    implements $BillCallerPaymentFfi_PaymentCopyWith<$Res> {
  _$BillCallerPaymentFfi_PaymentCopyWithImpl(this._self, this._then);

  final BillCallerPaymentFfi_Payment _self;
  final $Res Function(BillCallerPaymentFfi_Payment) _then;

/// Create a copy of BillCallerPaymentFfi
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? payer = null,Object? payee = null,Object? state = null,}) {
  return _then(BillCallerPaymentFfi_Payment(
payer: null == payer ? _self.payer : payer // ignore: cast_nullable_to_non_nullable
as BillIdentParticipantFfi,payee: null == payee ? _self.payee : payee // ignore: cast_nullable_to_non_nullable
as BillParticipantFfi,state: null == state ? _self.state : state // ignore: cast_nullable_to_non_nullable
as BillCallerPaymentStateFfi,
  ));
}

/// Create a copy of BillCallerPaymentFfi
/// with the given fields replaced by the non-null parameter values.
@override
@pragma('vm:prefer-inline')
$BillParticipantFfiCopyWith<$Res> get payee {
  
  return $BillParticipantFfiCopyWith<$Res>(_self.payee, (value) {
    return _then(_self.copyWith(payee: value));
  });
}
}

/// @nodoc


class BillCallerPaymentFfi_Recourse extends BillCallerPaymentFfi {
  const BillCallerPaymentFfi_Recourse({required this.recourser, required this.recoursee, required this.state}): super._();
  

 final  BillParticipantFfi recourser;
 final  BillIdentParticipantFfi recoursee;
@override final  BillCallerPaymentStateFfi state;

/// Create a copy of BillCallerPaymentFfi
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BillCallerPaymentFfi_RecourseCopyWith<BillCallerPaymentFfi_Recourse> get copyWith => _$BillCallerPaymentFfi_RecourseCopyWithImpl<BillCallerPaymentFfi_Recourse>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillCallerPaymentFfi_Recourse&&(identical(other.recourser, recourser) || other.recourser == recourser)&&(identical(other.recoursee, recoursee) || other.recoursee == recoursee)&&(identical(other.state, state) || other.state == state));
}


@override
int get hashCode => Object.hash(runtimeType,recourser,recoursee,state);

@override
String toString() {
  return 'BillCallerPaymentFfi.recourse(recourser: $recourser, recoursee: $recoursee, state: $state)';
}


}

/// @nodoc
abstract mixin class $BillCallerPaymentFfi_RecourseCopyWith<$Res> implements $BillCallerPaymentFfiCopyWith<$Res> {
  factory $BillCallerPaymentFfi_RecourseCopyWith(BillCallerPaymentFfi_Recourse value, $Res Function(BillCallerPaymentFfi_Recourse) _then) = _$BillCallerPaymentFfi_RecourseCopyWithImpl;
@override @useResult
$Res call({
 BillParticipantFfi recourser, BillIdentParticipantFfi recoursee, BillCallerPaymentStateFfi state
});


$BillParticipantFfiCopyWith<$Res> get recourser;

}
/// @nodoc
class _$BillCallerPaymentFfi_RecourseCopyWithImpl<$Res>
    implements $BillCallerPaymentFfi_RecourseCopyWith<$Res> {
  _$BillCallerPaymentFfi_RecourseCopyWithImpl(this._self, this._then);

  final BillCallerPaymentFfi_Recourse _self;
  final $Res Function(BillCallerPaymentFfi_Recourse) _then;

/// Create a copy of BillCallerPaymentFfi
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? recourser = null,Object? recoursee = null,Object? state = null,}) {
  return _then(BillCallerPaymentFfi_Recourse(
recourser: null == recourser ? _self.recourser : recourser // ignore: cast_nullable_to_non_nullable
as BillParticipantFfi,recoursee: null == recoursee ? _self.recoursee : recoursee // ignore: cast_nullable_to_non_nullable
as BillIdentParticipantFfi,state: null == state ? _self.state : state // ignore: cast_nullable_to_non_nullable
as BillCallerPaymentStateFfi,
  ));
}

/// Create a copy of BillCallerPaymentFfi
/// with the given fields replaced by the non-null parameter values.
@override
@pragma('vm:prefer-inline')
$BillParticipantFfiCopyWith<$Res> get recourser {
  
  return $BillParticipantFfiCopyWith<$Res>(_self.recourser, (value) {
    return _then(_self.copyWith(recourser: value));
  });
}
}

/// @nodoc
mixin _$BillCurrentWaitingStateFfi {

 Object get field0;



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillCurrentWaitingStateFfi&&const DeepCollectionEquality().equals(other.field0, field0));
}


@override
int get hashCode => Object.hash(runtimeType,const DeepCollectionEquality().hash(field0));

@override
String toString() {
  return 'BillCurrentWaitingStateFfi(field0: $field0)';
}


}

/// @nodoc
class $BillCurrentWaitingStateFfiCopyWith<$Res>  {
$BillCurrentWaitingStateFfiCopyWith(BillCurrentWaitingStateFfi _, $Res Function(BillCurrentWaitingStateFfi) __);
}


/// Adds pattern-matching-related methods to [BillCurrentWaitingStateFfi].
extension BillCurrentWaitingStateFfiPatterns on BillCurrentWaitingStateFfi {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( BillCurrentWaitingStateFfi_Sell value)?  sell,TResult Function( BillCurrentWaitingStateFfi_Payment value)?  payment,TResult Function( BillCurrentWaitingStateFfi_Recourse value)?  recourse,required TResult orElse(),}){
final _that = this;
switch (_that) {
case BillCurrentWaitingStateFfi_Sell() when sell != null:
return sell(_that);case BillCurrentWaitingStateFfi_Payment() when payment != null:
return payment(_that);case BillCurrentWaitingStateFfi_Recourse() when recourse != null:
return recourse(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( BillCurrentWaitingStateFfi_Sell value)  sell,required TResult Function( BillCurrentWaitingStateFfi_Payment value)  payment,required TResult Function( BillCurrentWaitingStateFfi_Recourse value)  recourse,}){
final _that = this;
switch (_that) {
case BillCurrentWaitingStateFfi_Sell():
return sell(_that);case BillCurrentWaitingStateFfi_Payment():
return payment(_that);case BillCurrentWaitingStateFfi_Recourse():
return recourse(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( BillCurrentWaitingStateFfi_Sell value)?  sell,TResult? Function( BillCurrentWaitingStateFfi_Payment value)?  payment,TResult? Function( BillCurrentWaitingStateFfi_Recourse value)?  recourse,}){
final _that = this;
switch (_that) {
case BillCurrentWaitingStateFfi_Sell() when sell != null:
return sell(_that);case BillCurrentWaitingStateFfi_Payment() when payment != null:
return payment(_that);case BillCurrentWaitingStateFfi_Recourse() when recourse != null:
return recourse(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( BillWaitingForSellStateFfi field0)?  sell,TResult Function( BillWaitingForPaymentStateFfi field0)?  payment,TResult Function( BillWaitingForRecourseStateFfi field0)?  recourse,required TResult orElse(),}) {final _that = this;
switch (_that) {
case BillCurrentWaitingStateFfi_Sell() when sell != null:
return sell(_that.field0);case BillCurrentWaitingStateFfi_Payment() when payment != null:
return payment(_that.field0);case BillCurrentWaitingStateFfi_Recourse() when recourse != null:
return recourse(_that.field0);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( BillWaitingForSellStateFfi field0)  sell,required TResult Function( BillWaitingForPaymentStateFfi field0)  payment,required TResult Function( BillWaitingForRecourseStateFfi field0)  recourse,}) {final _that = this;
switch (_that) {
case BillCurrentWaitingStateFfi_Sell():
return sell(_that.field0);case BillCurrentWaitingStateFfi_Payment():
return payment(_that.field0);case BillCurrentWaitingStateFfi_Recourse():
return recourse(_that.field0);}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( BillWaitingForSellStateFfi field0)?  sell,TResult? Function( BillWaitingForPaymentStateFfi field0)?  payment,TResult? Function( BillWaitingForRecourseStateFfi field0)?  recourse,}) {final _that = this;
switch (_that) {
case BillCurrentWaitingStateFfi_Sell() when sell != null:
return sell(_that.field0);case BillCurrentWaitingStateFfi_Payment() when payment != null:
return payment(_that.field0);case BillCurrentWaitingStateFfi_Recourse() when recourse != null:
return recourse(_that.field0);case _:
  return null;

}
}

}

/// @nodoc


class BillCurrentWaitingStateFfi_Sell extends BillCurrentWaitingStateFfi {
  const BillCurrentWaitingStateFfi_Sell(this.field0): super._();
  

@override final  BillWaitingForSellStateFfi field0;

/// Create a copy of BillCurrentWaitingStateFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BillCurrentWaitingStateFfi_SellCopyWith<BillCurrentWaitingStateFfi_Sell> get copyWith => _$BillCurrentWaitingStateFfi_SellCopyWithImpl<BillCurrentWaitingStateFfi_Sell>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillCurrentWaitingStateFfi_Sell&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'BillCurrentWaitingStateFfi.sell(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $BillCurrentWaitingStateFfi_SellCopyWith<$Res> implements $BillCurrentWaitingStateFfiCopyWith<$Res> {
  factory $BillCurrentWaitingStateFfi_SellCopyWith(BillCurrentWaitingStateFfi_Sell value, $Res Function(BillCurrentWaitingStateFfi_Sell) _then) = _$BillCurrentWaitingStateFfi_SellCopyWithImpl;
@useResult
$Res call({
 BillWaitingForSellStateFfi field0
});




}
/// @nodoc
class _$BillCurrentWaitingStateFfi_SellCopyWithImpl<$Res>
    implements $BillCurrentWaitingStateFfi_SellCopyWith<$Res> {
  _$BillCurrentWaitingStateFfi_SellCopyWithImpl(this._self, this._then);

  final BillCurrentWaitingStateFfi_Sell _self;
  final $Res Function(BillCurrentWaitingStateFfi_Sell) _then;

/// Create a copy of BillCurrentWaitingStateFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(BillCurrentWaitingStateFfi_Sell(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BillWaitingForSellStateFfi,
  ));
}


}

/// @nodoc


class BillCurrentWaitingStateFfi_Payment extends BillCurrentWaitingStateFfi {
  const BillCurrentWaitingStateFfi_Payment(this.field0): super._();
  

@override final  BillWaitingForPaymentStateFfi field0;

/// Create a copy of BillCurrentWaitingStateFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BillCurrentWaitingStateFfi_PaymentCopyWith<BillCurrentWaitingStateFfi_Payment> get copyWith => _$BillCurrentWaitingStateFfi_PaymentCopyWithImpl<BillCurrentWaitingStateFfi_Payment>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillCurrentWaitingStateFfi_Payment&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'BillCurrentWaitingStateFfi.payment(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $BillCurrentWaitingStateFfi_PaymentCopyWith<$Res> implements $BillCurrentWaitingStateFfiCopyWith<$Res> {
  factory $BillCurrentWaitingStateFfi_PaymentCopyWith(BillCurrentWaitingStateFfi_Payment value, $Res Function(BillCurrentWaitingStateFfi_Payment) _then) = _$BillCurrentWaitingStateFfi_PaymentCopyWithImpl;
@useResult
$Res call({
 BillWaitingForPaymentStateFfi field0
});




}
/// @nodoc
class _$BillCurrentWaitingStateFfi_PaymentCopyWithImpl<$Res>
    implements $BillCurrentWaitingStateFfi_PaymentCopyWith<$Res> {
  _$BillCurrentWaitingStateFfi_PaymentCopyWithImpl(this._self, this._then);

  final BillCurrentWaitingStateFfi_Payment _self;
  final $Res Function(BillCurrentWaitingStateFfi_Payment) _then;

/// Create a copy of BillCurrentWaitingStateFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(BillCurrentWaitingStateFfi_Payment(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BillWaitingForPaymentStateFfi,
  ));
}


}

/// @nodoc


class BillCurrentWaitingStateFfi_Recourse extends BillCurrentWaitingStateFfi {
  const BillCurrentWaitingStateFfi_Recourse(this.field0): super._();
  

@override final  BillWaitingForRecourseStateFfi field0;

/// Create a copy of BillCurrentWaitingStateFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BillCurrentWaitingStateFfi_RecourseCopyWith<BillCurrentWaitingStateFfi_Recourse> get copyWith => _$BillCurrentWaitingStateFfi_RecourseCopyWithImpl<BillCurrentWaitingStateFfi_Recourse>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillCurrentWaitingStateFfi_Recourse&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'BillCurrentWaitingStateFfi.recourse(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $BillCurrentWaitingStateFfi_RecourseCopyWith<$Res> implements $BillCurrentWaitingStateFfiCopyWith<$Res> {
  factory $BillCurrentWaitingStateFfi_RecourseCopyWith(BillCurrentWaitingStateFfi_Recourse value, $Res Function(BillCurrentWaitingStateFfi_Recourse) _then) = _$BillCurrentWaitingStateFfi_RecourseCopyWithImpl;
@useResult
$Res call({
 BillWaitingForRecourseStateFfi field0
});




}
/// @nodoc
class _$BillCurrentWaitingStateFfi_RecourseCopyWithImpl<$Res>
    implements $BillCurrentWaitingStateFfi_RecourseCopyWith<$Res> {
  _$BillCurrentWaitingStateFfi_RecourseCopyWithImpl(this._self, this._then);

  final BillCurrentWaitingStateFfi_Recourse _self;
  final $Res Function(BillCurrentWaitingStateFfi_Recourse) _then;

/// Create a copy of BillCurrentWaitingStateFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(BillCurrentWaitingStateFfi_Recourse(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BillWaitingForRecourseStateFfi,
  ));
}


}

/// @nodoc
mixin _$BillParticipantFfi {

 Object get field0;



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillParticipantFfi&&const DeepCollectionEquality().equals(other.field0, field0));
}


@override
int get hashCode => Object.hash(runtimeType,const DeepCollectionEquality().hash(field0));

@override
String toString() {
  return 'BillParticipantFfi(field0: $field0)';
}


}

/// @nodoc
class $BillParticipantFfiCopyWith<$Res>  {
$BillParticipantFfiCopyWith(BillParticipantFfi _, $Res Function(BillParticipantFfi) __);
}


/// Adds pattern-matching-related methods to [BillParticipantFfi].
extension BillParticipantFfiPatterns on BillParticipantFfi {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( BillParticipantFfi_Anon value)?  anon,TResult Function( BillParticipantFfi_Ident value)?  ident,required TResult orElse(),}){
final _that = this;
switch (_that) {
case BillParticipantFfi_Anon() when anon != null:
return anon(_that);case BillParticipantFfi_Ident() when ident != null:
return ident(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( BillParticipantFfi_Anon value)  anon,required TResult Function( BillParticipantFfi_Ident value)  ident,}){
final _that = this;
switch (_that) {
case BillParticipantFfi_Anon():
return anon(_that);case BillParticipantFfi_Ident():
return ident(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( BillParticipantFfi_Anon value)?  anon,TResult? Function( BillParticipantFfi_Ident value)?  ident,}){
final _that = this;
switch (_that) {
case BillParticipantFfi_Anon() when anon != null:
return anon(_that);case BillParticipantFfi_Ident() when ident != null:
return ident(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( BillAnonParticipantFfi field0)?  anon,TResult Function( BillIdentParticipantFfi field0)?  ident,required TResult orElse(),}) {final _that = this;
switch (_that) {
case BillParticipantFfi_Anon() when anon != null:
return anon(_that.field0);case BillParticipantFfi_Ident() when ident != null:
return ident(_that.field0);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( BillAnonParticipantFfi field0)  anon,required TResult Function( BillIdentParticipantFfi field0)  ident,}) {final _that = this;
switch (_that) {
case BillParticipantFfi_Anon():
return anon(_that.field0);case BillParticipantFfi_Ident():
return ident(_that.field0);}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( BillAnonParticipantFfi field0)?  anon,TResult? Function( BillIdentParticipantFfi field0)?  ident,}) {final _that = this;
switch (_that) {
case BillParticipantFfi_Anon() when anon != null:
return anon(_that.field0);case BillParticipantFfi_Ident() when ident != null:
return ident(_that.field0);case _:
  return null;

}
}

}

/// @nodoc


class BillParticipantFfi_Anon extends BillParticipantFfi {
  const BillParticipantFfi_Anon(this.field0): super._();
  

@override final  BillAnonParticipantFfi field0;

/// Create a copy of BillParticipantFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BillParticipantFfi_AnonCopyWith<BillParticipantFfi_Anon> get copyWith => _$BillParticipantFfi_AnonCopyWithImpl<BillParticipantFfi_Anon>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillParticipantFfi_Anon&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'BillParticipantFfi.anon(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $BillParticipantFfi_AnonCopyWith<$Res> implements $BillParticipantFfiCopyWith<$Res> {
  factory $BillParticipantFfi_AnonCopyWith(BillParticipantFfi_Anon value, $Res Function(BillParticipantFfi_Anon) _then) = _$BillParticipantFfi_AnonCopyWithImpl;
@useResult
$Res call({
 BillAnonParticipantFfi field0
});




}
/// @nodoc
class _$BillParticipantFfi_AnonCopyWithImpl<$Res>
    implements $BillParticipantFfi_AnonCopyWith<$Res> {
  _$BillParticipantFfi_AnonCopyWithImpl(this._self, this._then);

  final BillParticipantFfi_Anon _self;
  final $Res Function(BillParticipantFfi_Anon) _then;

/// Create a copy of BillParticipantFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(BillParticipantFfi_Anon(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BillAnonParticipantFfi,
  ));
}


}

/// @nodoc


class BillParticipantFfi_Ident extends BillParticipantFfi {
  const BillParticipantFfi_Ident(this.field0): super._();
  

@override final  BillIdentParticipantFfi field0;

/// Create a copy of BillParticipantFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BillParticipantFfi_IdentCopyWith<BillParticipantFfi_Ident> get copyWith => _$BillParticipantFfi_IdentCopyWithImpl<BillParticipantFfi_Ident>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillParticipantFfi_Ident&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'BillParticipantFfi.ident(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $BillParticipantFfi_IdentCopyWith<$Res> implements $BillParticipantFfiCopyWith<$Res> {
  factory $BillParticipantFfi_IdentCopyWith(BillParticipantFfi_Ident value, $Res Function(BillParticipantFfi_Ident) _then) = _$BillParticipantFfi_IdentCopyWithImpl;
@useResult
$Res call({
 BillIdentParticipantFfi field0
});




}
/// @nodoc
class _$BillParticipantFfi_IdentCopyWithImpl<$Res>
    implements $BillParticipantFfi_IdentCopyWith<$Res> {
  _$BillParticipantFfi_IdentCopyWithImpl(this._self, this._then);

  final BillParticipantFfi_Ident _self;
  final $Res Function(BillParticipantFfi_Ident) _then;

/// Create a copy of BillParticipantFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(BillParticipantFfi_Ident(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BillIdentParticipantFfi,
  ));
}


}

/// @nodoc
mixin _$BillPaymentStateFfi {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillPaymentStateFfi);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'BillPaymentStateFfi()';
}


}

/// @nodoc
class $BillPaymentStateFfiCopyWith<$Res>  {
$BillPaymentStateFfiCopyWith(BillPaymentStateFfi _, $Res Function(BillPaymentStateFfi) __);
}


/// Adds pattern-matching-related methods to [BillPaymentStateFfi].
extension BillPaymentStateFfiPatterns on BillPaymentStateFfi {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( BillPaymentStateFfi_None value)?  none,TResult Function( BillPaymentStateFfi_Requested value)?  requested,TResult Function( BillPaymentStateFfi_Paid value)?  paid,TResult Function( BillPaymentStateFfi_Expired value)?  expired,TResult Function( BillPaymentStateFfi_Rejected value)?  rejected,required TResult orElse(),}){
final _that = this;
switch (_that) {
case BillPaymentStateFfi_None() when none != null:
return none(_that);case BillPaymentStateFfi_Requested() when requested != null:
return requested(_that);case BillPaymentStateFfi_Paid() when paid != null:
return paid(_that);case BillPaymentStateFfi_Expired() when expired != null:
return expired(_that);case BillPaymentStateFfi_Rejected() when rejected != null:
return rejected(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( BillPaymentStateFfi_None value)  none,required TResult Function( BillPaymentStateFfi_Requested value)  requested,required TResult Function( BillPaymentStateFfi_Paid value)  paid,required TResult Function( BillPaymentStateFfi_Expired value)  expired,required TResult Function( BillPaymentStateFfi_Rejected value)  rejected,}){
final _that = this;
switch (_that) {
case BillPaymentStateFfi_None():
return none(_that);case BillPaymentStateFfi_Requested():
return requested(_that);case BillPaymentStateFfi_Paid():
return paid(_that);case BillPaymentStateFfi_Expired():
return expired(_that);case BillPaymentStateFfi_Rejected():
return rejected(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( BillPaymentStateFfi_None value)?  none,TResult? Function( BillPaymentStateFfi_Requested value)?  requested,TResult? Function( BillPaymentStateFfi_Paid value)?  paid,TResult? Function( BillPaymentStateFfi_Expired value)?  expired,TResult? Function( BillPaymentStateFfi_Rejected value)?  rejected,}){
final _that = this;
switch (_that) {
case BillPaymentStateFfi_None() when none != null:
return none(_that);case BillPaymentStateFfi_Requested() when requested != null:
return requested(_that);case BillPaymentStateFfi_Paid() when paid != null:
return paid(_that);case BillPaymentStateFfi_Expired() when expired != null:
return expired(_that);case BillPaymentStateFfi_Rejected() when rejected != null:
return rejected(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function()?  none,TResult Function( BigInt field0)?  requested,TResult Function( BigInt field0)?  paid,TResult Function( BigInt field0)?  expired,TResult Function( BigInt field0)?  rejected,required TResult orElse(),}) {final _that = this;
switch (_that) {
case BillPaymentStateFfi_None() when none != null:
return none();case BillPaymentStateFfi_Requested() when requested != null:
return requested(_that.field0);case BillPaymentStateFfi_Paid() when paid != null:
return paid(_that.field0);case BillPaymentStateFfi_Expired() when expired != null:
return expired(_that.field0);case BillPaymentStateFfi_Rejected() when rejected != null:
return rejected(_that.field0);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function()  none,required TResult Function( BigInt field0)  requested,required TResult Function( BigInt field0)  paid,required TResult Function( BigInt field0)  expired,required TResult Function( BigInt field0)  rejected,}) {final _that = this;
switch (_that) {
case BillPaymentStateFfi_None():
return none();case BillPaymentStateFfi_Requested():
return requested(_that.field0);case BillPaymentStateFfi_Paid():
return paid(_that.field0);case BillPaymentStateFfi_Expired():
return expired(_that.field0);case BillPaymentStateFfi_Rejected():
return rejected(_that.field0);}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function()?  none,TResult? Function( BigInt field0)?  requested,TResult? Function( BigInt field0)?  paid,TResult? Function( BigInt field0)?  expired,TResult? Function( BigInt field0)?  rejected,}) {final _that = this;
switch (_that) {
case BillPaymentStateFfi_None() when none != null:
return none();case BillPaymentStateFfi_Requested() when requested != null:
return requested(_that.field0);case BillPaymentStateFfi_Paid() when paid != null:
return paid(_that.field0);case BillPaymentStateFfi_Expired() when expired != null:
return expired(_that.field0);case BillPaymentStateFfi_Rejected() when rejected != null:
return rejected(_that.field0);case _:
  return null;

}
}

}

/// @nodoc


class BillPaymentStateFfi_None extends BillPaymentStateFfi {
  const BillPaymentStateFfi_None(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillPaymentStateFfi_None);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'BillPaymentStateFfi.none()';
}


}




/// @nodoc


class BillPaymentStateFfi_Requested extends BillPaymentStateFfi {
  const BillPaymentStateFfi_Requested(this.field0): super._();
  

 final  BigInt field0;

/// Create a copy of BillPaymentStateFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BillPaymentStateFfi_RequestedCopyWith<BillPaymentStateFfi_Requested> get copyWith => _$BillPaymentStateFfi_RequestedCopyWithImpl<BillPaymentStateFfi_Requested>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillPaymentStateFfi_Requested&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'BillPaymentStateFfi.requested(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $BillPaymentStateFfi_RequestedCopyWith<$Res> implements $BillPaymentStateFfiCopyWith<$Res> {
  factory $BillPaymentStateFfi_RequestedCopyWith(BillPaymentStateFfi_Requested value, $Res Function(BillPaymentStateFfi_Requested) _then) = _$BillPaymentStateFfi_RequestedCopyWithImpl;
@useResult
$Res call({
 BigInt field0
});




}
/// @nodoc
class _$BillPaymentStateFfi_RequestedCopyWithImpl<$Res>
    implements $BillPaymentStateFfi_RequestedCopyWith<$Res> {
  _$BillPaymentStateFfi_RequestedCopyWithImpl(this._self, this._then);

  final BillPaymentStateFfi_Requested _self;
  final $Res Function(BillPaymentStateFfi_Requested) _then;

/// Create a copy of BillPaymentStateFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(BillPaymentStateFfi_Requested(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class BillPaymentStateFfi_Paid extends BillPaymentStateFfi {
  const BillPaymentStateFfi_Paid(this.field0): super._();
  

 final  BigInt field0;

/// Create a copy of BillPaymentStateFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BillPaymentStateFfi_PaidCopyWith<BillPaymentStateFfi_Paid> get copyWith => _$BillPaymentStateFfi_PaidCopyWithImpl<BillPaymentStateFfi_Paid>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillPaymentStateFfi_Paid&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'BillPaymentStateFfi.paid(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $BillPaymentStateFfi_PaidCopyWith<$Res> implements $BillPaymentStateFfiCopyWith<$Res> {
  factory $BillPaymentStateFfi_PaidCopyWith(BillPaymentStateFfi_Paid value, $Res Function(BillPaymentStateFfi_Paid) _then) = _$BillPaymentStateFfi_PaidCopyWithImpl;
@useResult
$Res call({
 BigInt field0
});




}
/// @nodoc
class _$BillPaymentStateFfi_PaidCopyWithImpl<$Res>
    implements $BillPaymentStateFfi_PaidCopyWith<$Res> {
  _$BillPaymentStateFfi_PaidCopyWithImpl(this._self, this._then);

  final BillPaymentStateFfi_Paid _self;
  final $Res Function(BillPaymentStateFfi_Paid) _then;

/// Create a copy of BillPaymentStateFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(BillPaymentStateFfi_Paid(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class BillPaymentStateFfi_Expired extends BillPaymentStateFfi {
  const BillPaymentStateFfi_Expired(this.field0): super._();
  

 final  BigInt field0;

/// Create a copy of BillPaymentStateFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BillPaymentStateFfi_ExpiredCopyWith<BillPaymentStateFfi_Expired> get copyWith => _$BillPaymentStateFfi_ExpiredCopyWithImpl<BillPaymentStateFfi_Expired>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillPaymentStateFfi_Expired&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'BillPaymentStateFfi.expired(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $BillPaymentStateFfi_ExpiredCopyWith<$Res> implements $BillPaymentStateFfiCopyWith<$Res> {
  factory $BillPaymentStateFfi_ExpiredCopyWith(BillPaymentStateFfi_Expired value, $Res Function(BillPaymentStateFfi_Expired) _then) = _$BillPaymentStateFfi_ExpiredCopyWithImpl;
@useResult
$Res call({
 BigInt field0
});




}
/// @nodoc
class _$BillPaymentStateFfi_ExpiredCopyWithImpl<$Res>
    implements $BillPaymentStateFfi_ExpiredCopyWith<$Res> {
  _$BillPaymentStateFfi_ExpiredCopyWithImpl(this._self, this._then);

  final BillPaymentStateFfi_Expired _self;
  final $Res Function(BillPaymentStateFfi_Expired) _then;

/// Create a copy of BillPaymentStateFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(BillPaymentStateFfi_Expired(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class BillPaymentStateFfi_Rejected extends BillPaymentStateFfi {
  const BillPaymentStateFfi_Rejected(this.field0): super._();
  

 final  BigInt field0;

/// Create a copy of BillPaymentStateFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$BillPaymentStateFfi_RejectedCopyWith<BillPaymentStateFfi_Rejected> get copyWith => _$BillPaymentStateFfi_RejectedCopyWithImpl<BillPaymentStateFfi_Rejected>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is BillPaymentStateFfi_Rejected&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'BillPaymentStateFfi.rejected(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $BillPaymentStateFfi_RejectedCopyWith<$Res> implements $BillPaymentStateFfiCopyWith<$Res> {
  factory $BillPaymentStateFfi_RejectedCopyWith(BillPaymentStateFfi_Rejected value, $Res Function(BillPaymentStateFfi_Rejected) _then) = _$BillPaymentStateFfi_RejectedCopyWithImpl;
@useResult
$Res call({
 BigInt field0
});




}
/// @nodoc
class _$BillPaymentStateFfi_RejectedCopyWithImpl<$Res>
    implements $BillPaymentStateFfi_RejectedCopyWith<$Res> {
  _$BillPaymentStateFfi_RejectedCopyWithImpl(this._self, this._then);

  final BillPaymentStateFfi_Rejected _self;
  final $Res Function(BillPaymentStateFfi_Rejected) _then;

/// Create a copy of BillPaymentStateFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(BillPaymentStateFfi_Rejected(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc
mixin _$LightBillParticipantFfi {

 Object get field0;



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is LightBillParticipantFfi&&const DeepCollectionEquality().equals(other.field0, field0));
}


@override
int get hashCode => Object.hash(runtimeType,const DeepCollectionEquality().hash(field0));

@override
String toString() {
  return 'LightBillParticipantFfi(field0: $field0)';
}


}

/// @nodoc
class $LightBillParticipantFfiCopyWith<$Res>  {
$LightBillParticipantFfiCopyWith(LightBillParticipantFfi _, $Res Function(LightBillParticipantFfi) __);
}


/// Adds pattern-matching-related methods to [LightBillParticipantFfi].
extension LightBillParticipantFfiPatterns on LightBillParticipantFfi {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( LightBillParticipantFfi_Anon value)?  anon,TResult Function( LightBillParticipantFfi_Ident value)?  ident,required TResult orElse(),}){
final _that = this;
switch (_that) {
case LightBillParticipantFfi_Anon() when anon != null:
return anon(_that);case LightBillParticipantFfi_Ident() when ident != null:
return ident(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( LightBillParticipantFfi_Anon value)  anon,required TResult Function( LightBillParticipantFfi_Ident value)  ident,}){
final _that = this;
switch (_that) {
case LightBillParticipantFfi_Anon():
return anon(_that);case LightBillParticipantFfi_Ident():
return ident(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( LightBillParticipantFfi_Anon value)?  anon,TResult? Function( LightBillParticipantFfi_Ident value)?  ident,}){
final _that = this;
switch (_that) {
case LightBillParticipantFfi_Anon() when anon != null:
return anon(_that);case LightBillParticipantFfi_Ident() when ident != null:
return ident(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( LightBillAnonParticipantFfi field0)?  anon,TResult Function( LightBillIdentParticipantWithAddressFfi field0)?  ident,required TResult orElse(),}) {final _that = this;
switch (_that) {
case LightBillParticipantFfi_Anon() when anon != null:
return anon(_that.field0);case LightBillParticipantFfi_Ident() when ident != null:
return ident(_that.field0);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( LightBillAnonParticipantFfi field0)  anon,required TResult Function( LightBillIdentParticipantWithAddressFfi field0)  ident,}) {final _that = this;
switch (_that) {
case LightBillParticipantFfi_Anon():
return anon(_that.field0);case LightBillParticipantFfi_Ident():
return ident(_that.field0);}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( LightBillAnonParticipantFfi field0)?  anon,TResult? Function( LightBillIdentParticipantWithAddressFfi field0)?  ident,}) {final _that = this;
switch (_that) {
case LightBillParticipantFfi_Anon() when anon != null:
return anon(_that.field0);case LightBillParticipantFfi_Ident() when ident != null:
return ident(_that.field0);case _:
  return null;

}
}

}

/// @nodoc


class LightBillParticipantFfi_Anon extends LightBillParticipantFfi {
  const LightBillParticipantFfi_Anon(this.field0): super._();
  

@override final  LightBillAnonParticipantFfi field0;

/// Create a copy of LightBillParticipantFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$LightBillParticipantFfi_AnonCopyWith<LightBillParticipantFfi_Anon> get copyWith => _$LightBillParticipantFfi_AnonCopyWithImpl<LightBillParticipantFfi_Anon>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is LightBillParticipantFfi_Anon&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'LightBillParticipantFfi.anon(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $LightBillParticipantFfi_AnonCopyWith<$Res> implements $LightBillParticipantFfiCopyWith<$Res> {
  factory $LightBillParticipantFfi_AnonCopyWith(LightBillParticipantFfi_Anon value, $Res Function(LightBillParticipantFfi_Anon) _then) = _$LightBillParticipantFfi_AnonCopyWithImpl;
@useResult
$Res call({
 LightBillAnonParticipantFfi field0
});




}
/// @nodoc
class _$LightBillParticipantFfi_AnonCopyWithImpl<$Res>
    implements $LightBillParticipantFfi_AnonCopyWith<$Res> {
  _$LightBillParticipantFfi_AnonCopyWithImpl(this._self, this._then);

  final LightBillParticipantFfi_Anon _self;
  final $Res Function(LightBillParticipantFfi_Anon) _then;

/// Create a copy of LightBillParticipantFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(LightBillParticipantFfi_Anon(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as LightBillAnonParticipantFfi,
  ));
}


}

/// @nodoc


class LightBillParticipantFfi_Ident extends LightBillParticipantFfi {
  const LightBillParticipantFfi_Ident(this.field0): super._();
  

@override final  LightBillIdentParticipantWithAddressFfi field0;

/// Create a copy of LightBillParticipantFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$LightBillParticipantFfi_IdentCopyWith<LightBillParticipantFfi_Ident> get copyWith => _$LightBillParticipantFfi_IdentCopyWithImpl<LightBillParticipantFfi_Ident>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is LightBillParticipantFfi_Ident&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'LightBillParticipantFfi.ident(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $LightBillParticipantFfi_IdentCopyWith<$Res> implements $LightBillParticipantFfiCopyWith<$Res> {
  factory $LightBillParticipantFfi_IdentCopyWith(LightBillParticipantFfi_Ident value, $Res Function(LightBillParticipantFfi_Ident) _then) = _$LightBillParticipantFfi_IdentCopyWithImpl;
@useResult
$Res call({
 LightBillIdentParticipantWithAddressFfi field0
});




}
/// @nodoc
class _$LightBillParticipantFfi_IdentCopyWithImpl<$Res>
    implements $LightBillParticipantFfi_IdentCopyWith<$Res> {
  _$LightBillParticipantFfi_IdentCopyWithImpl(this._self, this._then);

  final LightBillParticipantFfi_Ident _self;
  final $Res Function(LightBillParticipantFfi_Ident) _then;

/// Create a copy of LightBillParticipantFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(LightBillParticipantFfi_Ident(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as LightBillIdentParticipantWithAddressFfi,
  ));
}


}

/// @nodoc
mixin _$PastPaymentResultFfi {

 Object get field0;



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is PastPaymentResultFfi&&const DeepCollectionEquality().equals(other.field0, field0));
}


@override
int get hashCode => Object.hash(runtimeType,const DeepCollectionEquality().hash(field0));

@override
String toString() {
  return 'PastPaymentResultFfi(field0: $field0)';
}


}

/// @nodoc
class $PastPaymentResultFfiCopyWith<$Res>  {
$PastPaymentResultFfiCopyWith(PastPaymentResultFfi _, $Res Function(PastPaymentResultFfi) __);
}


/// Adds pattern-matching-related methods to [PastPaymentResultFfi].
extension PastPaymentResultFfiPatterns on PastPaymentResultFfi {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( PastPaymentResultFfi_Sell value)?  sell,TResult Function( PastPaymentResultFfi_Payment value)?  payment,TResult Function( PastPaymentResultFfi_Recourse value)?  recourse,required TResult orElse(),}){
final _that = this;
switch (_that) {
case PastPaymentResultFfi_Sell() when sell != null:
return sell(_that);case PastPaymentResultFfi_Payment() when payment != null:
return payment(_that);case PastPaymentResultFfi_Recourse() when recourse != null:
return recourse(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( PastPaymentResultFfi_Sell value)  sell,required TResult Function( PastPaymentResultFfi_Payment value)  payment,required TResult Function( PastPaymentResultFfi_Recourse value)  recourse,}){
final _that = this;
switch (_that) {
case PastPaymentResultFfi_Sell():
return sell(_that);case PastPaymentResultFfi_Payment():
return payment(_that);case PastPaymentResultFfi_Recourse():
return recourse(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( PastPaymentResultFfi_Sell value)?  sell,TResult? Function( PastPaymentResultFfi_Payment value)?  payment,TResult? Function( PastPaymentResultFfi_Recourse value)?  recourse,}){
final _that = this;
switch (_that) {
case PastPaymentResultFfi_Sell() when sell != null:
return sell(_that);case PastPaymentResultFfi_Payment() when payment != null:
return payment(_that);case PastPaymentResultFfi_Recourse() when recourse != null:
return recourse(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( PastPaymentDataSellFfi field0)?  sell,TResult Function( PastPaymentDataPaymentFfi field0)?  payment,TResult Function( PastPaymentDataRecourseFfi field0)?  recourse,required TResult orElse(),}) {final _that = this;
switch (_that) {
case PastPaymentResultFfi_Sell() when sell != null:
return sell(_that.field0);case PastPaymentResultFfi_Payment() when payment != null:
return payment(_that.field0);case PastPaymentResultFfi_Recourse() when recourse != null:
return recourse(_that.field0);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( PastPaymentDataSellFfi field0)  sell,required TResult Function( PastPaymentDataPaymentFfi field0)  payment,required TResult Function( PastPaymentDataRecourseFfi field0)  recourse,}) {final _that = this;
switch (_that) {
case PastPaymentResultFfi_Sell():
return sell(_that.field0);case PastPaymentResultFfi_Payment():
return payment(_that.field0);case PastPaymentResultFfi_Recourse():
return recourse(_that.field0);}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( PastPaymentDataSellFfi field0)?  sell,TResult? Function( PastPaymentDataPaymentFfi field0)?  payment,TResult? Function( PastPaymentDataRecourseFfi field0)?  recourse,}) {final _that = this;
switch (_that) {
case PastPaymentResultFfi_Sell() when sell != null:
return sell(_that.field0);case PastPaymentResultFfi_Payment() when payment != null:
return payment(_that.field0);case PastPaymentResultFfi_Recourse() when recourse != null:
return recourse(_that.field0);case _:
  return null;

}
}

}

/// @nodoc


class PastPaymentResultFfi_Sell extends PastPaymentResultFfi {
  const PastPaymentResultFfi_Sell(this.field0): super._();
  

@override final  PastPaymentDataSellFfi field0;

/// Create a copy of PastPaymentResultFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$PastPaymentResultFfi_SellCopyWith<PastPaymentResultFfi_Sell> get copyWith => _$PastPaymentResultFfi_SellCopyWithImpl<PastPaymentResultFfi_Sell>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is PastPaymentResultFfi_Sell&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'PastPaymentResultFfi.sell(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $PastPaymentResultFfi_SellCopyWith<$Res> implements $PastPaymentResultFfiCopyWith<$Res> {
  factory $PastPaymentResultFfi_SellCopyWith(PastPaymentResultFfi_Sell value, $Res Function(PastPaymentResultFfi_Sell) _then) = _$PastPaymentResultFfi_SellCopyWithImpl;
@useResult
$Res call({
 PastPaymentDataSellFfi field0
});




}
/// @nodoc
class _$PastPaymentResultFfi_SellCopyWithImpl<$Res>
    implements $PastPaymentResultFfi_SellCopyWith<$Res> {
  _$PastPaymentResultFfi_SellCopyWithImpl(this._self, this._then);

  final PastPaymentResultFfi_Sell _self;
  final $Res Function(PastPaymentResultFfi_Sell) _then;

/// Create a copy of PastPaymentResultFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(PastPaymentResultFfi_Sell(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as PastPaymentDataSellFfi,
  ));
}


}

/// @nodoc


class PastPaymentResultFfi_Payment extends PastPaymentResultFfi {
  const PastPaymentResultFfi_Payment(this.field0): super._();
  

@override final  PastPaymentDataPaymentFfi field0;

/// Create a copy of PastPaymentResultFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$PastPaymentResultFfi_PaymentCopyWith<PastPaymentResultFfi_Payment> get copyWith => _$PastPaymentResultFfi_PaymentCopyWithImpl<PastPaymentResultFfi_Payment>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is PastPaymentResultFfi_Payment&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'PastPaymentResultFfi.payment(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $PastPaymentResultFfi_PaymentCopyWith<$Res> implements $PastPaymentResultFfiCopyWith<$Res> {
  factory $PastPaymentResultFfi_PaymentCopyWith(PastPaymentResultFfi_Payment value, $Res Function(PastPaymentResultFfi_Payment) _then) = _$PastPaymentResultFfi_PaymentCopyWithImpl;
@useResult
$Res call({
 PastPaymentDataPaymentFfi field0
});




}
/// @nodoc
class _$PastPaymentResultFfi_PaymentCopyWithImpl<$Res>
    implements $PastPaymentResultFfi_PaymentCopyWith<$Res> {
  _$PastPaymentResultFfi_PaymentCopyWithImpl(this._self, this._then);

  final PastPaymentResultFfi_Payment _self;
  final $Res Function(PastPaymentResultFfi_Payment) _then;

/// Create a copy of PastPaymentResultFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(PastPaymentResultFfi_Payment(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as PastPaymentDataPaymentFfi,
  ));
}


}

/// @nodoc


class PastPaymentResultFfi_Recourse extends PastPaymentResultFfi {
  const PastPaymentResultFfi_Recourse(this.field0): super._();
  

@override final  PastPaymentDataRecourseFfi field0;

/// Create a copy of PastPaymentResultFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$PastPaymentResultFfi_RecourseCopyWith<PastPaymentResultFfi_Recourse> get copyWith => _$PastPaymentResultFfi_RecourseCopyWithImpl<PastPaymentResultFfi_Recourse>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is PastPaymentResultFfi_Recourse&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'PastPaymentResultFfi.recourse(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $PastPaymentResultFfi_RecourseCopyWith<$Res> implements $PastPaymentResultFfiCopyWith<$Res> {
  factory $PastPaymentResultFfi_RecourseCopyWith(PastPaymentResultFfi_Recourse value, $Res Function(PastPaymentResultFfi_Recourse) _then) = _$PastPaymentResultFfi_RecourseCopyWithImpl;
@useResult
$Res call({
 PastPaymentDataRecourseFfi field0
});




}
/// @nodoc
class _$PastPaymentResultFfi_RecourseCopyWithImpl<$Res>
    implements $PastPaymentResultFfi_RecourseCopyWith<$Res> {
  _$PastPaymentResultFfi_RecourseCopyWithImpl(this._self, this._then);

  final PastPaymentResultFfi_Recourse _self;
  final $Res Function(PastPaymentResultFfi_Recourse) _then;

/// Create a copy of PastPaymentResultFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(PastPaymentResultFfi_Recourse(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as PastPaymentDataRecourseFfi,
  ));
}


}

/// @nodoc
mixin _$PaymentStatusFfi {

 BigInt get field0;
/// Create a copy of PaymentStatusFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$PaymentStatusFfiCopyWith<PaymentStatusFfi> get copyWith => _$PaymentStatusFfiCopyWithImpl<PaymentStatusFfi>(this as PaymentStatusFfi, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is PaymentStatusFfi&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'PaymentStatusFfi(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $PaymentStatusFfiCopyWith<$Res>  {
  factory $PaymentStatusFfiCopyWith(PaymentStatusFfi value, $Res Function(PaymentStatusFfi) _then) = _$PaymentStatusFfiCopyWithImpl;
@useResult
$Res call({
 BigInt field0
});




}
/// @nodoc
class _$PaymentStatusFfiCopyWithImpl<$Res>
    implements $PaymentStatusFfiCopyWith<$Res> {
  _$PaymentStatusFfiCopyWithImpl(this._self, this._then);

  final PaymentStatusFfi _self;
  final $Res Function(PaymentStatusFfi) _then;

/// Create a copy of PaymentStatusFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') @override $Res call({Object? field0 = null,}) {
  return _then(_self.copyWith(
field0: null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}

}


/// Adds pattern-matching-related methods to [PaymentStatusFfi].
extension PaymentStatusFfiPatterns on PaymentStatusFfi {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( PaymentStatusFfi_Requested value)?  requested,TResult Function( PaymentStatusFfi_Paid value)?  paid,TResult Function( PaymentStatusFfi_Rejected value)?  rejected,TResult Function( PaymentStatusFfi_Expired value)?  expired,required TResult orElse(),}){
final _that = this;
switch (_that) {
case PaymentStatusFfi_Requested() when requested != null:
return requested(_that);case PaymentStatusFfi_Paid() when paid != null:
return paid(_that);case PaymentStatusFfi_Rejected() when rejected != null:
return rejected(_that);case PaymentStatusFfi_Expired() when expired != null:
return expired(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( PaymentStatusFfi_Requested value)  requested,required TResult Function( PaymentStatusFfi_Paid value)  paid,required TResult Function( PaymentStatusFfi_Rejected value)  rejected,required TResult Function( PaymentStatusFfi_Expired value)  expired,}){
final _that = this;
switch (_that) {
case PaymentStatusFfi_Requested():
return requested(_that);case PaymentStatusFfi_Paid():
return paid(_that);case PaymentStatusFfi_Rejected():
return rejected(_that);case PaymentStatusFfi_Expired():
return expired(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( PaymentStatusFfi_Requested value)?  requested,TResult? Function( PaymentStatusFfi_Paid value)?  paid,TResult? Function( PaymentStatusFfi_Rejected value)?  rejected,TResult? Function( PaymentStatusFfi_Expired value)?  expired,}){
final _that = this;
switch (_that) {
case PaymentStatusFfi_Requested() when requested != null:
return requested(_that);case PaymentStatusFfi_Paid() when paid != null:
return paid(_that);case PaymentStatusFfi_Rejected() when rejected != null:
return rejected(_that);case PaymentStatusFfi_Expired() when expired != null:
return expired(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( BigInt field0)?  requested,TResult Function( BigInt field0)?  paid,TResult Function( BigInt field0)?  rejected,TResult Function( BigInt field0)?  expired,required TResult orElse(),}) {final _that = this;
switch (_that) {
case PaymentStatusFfi_Requested() when requested != null:
return requested(_that.field0);case PaymentStatusFfi_Paid() when paid != null:
return paid(_that.field0);case PaymentStatusFfi_Rejected() when rejected != null:
return rejected(_that.field0);case PaymentStatusFfi_Expired() when expired != null:
return expired(_that.field0);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( BigInt field0)  requested,required TResult Function( BigInt field0)  paid,required TResult Function( BigInt field0)  rejected,required TResult Function( BigInt field0)  expired,}) {final _that = this;
switch (_that) {
case PaymentStatusFfi_Requested():
return requested(_that.field0);case PaymentStatusFfi_Paid():
return paid(_that.field0);case PaymentStatusFfi_Rejected():
return rejected(_that.field0);case PaymentStatusFfi_Expired():
return expired(_that.field0);}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( BigInt field0)?  requested,TResult? Function( BigInt field0)?  paid,TResult? Function( BigInt field0)?  rejected,TResult? Function( BigInt field0)?  expired,}) {final _that = this;
switch (_that) {
case PaymentStatusFfi_Requested() when requested != null:
return requested(_that.field0);case PaymentStatusFfi_Paid() when paid != null:
return paid(_that.field0);case PaymentStatusFfi_Rejected() when rejected != null:
return rejected(_that.field0);case PaymentStatusFfi_Expired() when expired != null:
return expired(_that.field0);case _:
  return null;

}
}

}

/// @nodoc


class PaymentStatusFfi_Requested extends PaymentStatusFfi {
  const PaymentStatusFfi_Requested(this.field0): super._();
  

@override final  BigInt field0;

/// Create a copy of PaymentStatusFfi
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$PaymentStatusFfi_RequestedCopyWith<PaymentStatusFfi_Requested> get copyWith => _$PaymentStatusFfi_RequestedCopyWithImpl<PaymentStatusFfi_Requested>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is PaymentStatusFfi_Requested&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'PaymentStatusFfi.requested(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $PaymentStatusFfi_RequestedCopyWith<$Res> implements $PaymentStatusFfiCopyWith<$Res> {
  factory $PaymentStatusFfi_RequestedCopyWith(PaymentStatusFfi_Requested value, $Res Function(PaymentStatusFfi_Requested) _then) = _$PaymentStatusFfi_RequestedCopyWithImpl;
@override @useResult
$Res call({
 BigInt field0
});




}
/// @nodoc
class _$PaymentStatusFfi_RequestedCopyWithImpl<$Res>
    implements $PaymentStatusFfi_RequestedCopyWith<$Res> {
  _$PaymentStatusFfi_RequestedCopyWithImpl(this._self, this._then);

  final PaymentStatusFfi_Requested _self;
  final $Res Function(PaymentStatusFfi_Requested) _then;

/// Create a copy of PaymentStatusFfi
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(PaymentStatusFfi_Requested(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class PaymentStatusFfi_Paid extends PaymentStatusFfi {
  const PaymentStatusFfi_Paid(this.field0): super._();
  

@override final  BigInt field0;

/// Create a copy of PaymentStatusFfi
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$PaymentStatusFfi_PaidCopyWith<PaymentStatusFfi_Paid> get copyWith => _$PaymentStatusFfi_PaidCopyWithImpl<PaymentStatusFfi_Paid>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is PaymentStatusFfi_Paid&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'PaymentStatusFfi.paid(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $PaymentStatusFfi_PaidCopyWith<$Res> implements $PaymentStatusFfiCopyWith<$Res> {
  factory $PaymentStatusFfi_PaidCopyWith(PaymentStatusFfi_Paid value, $Res Function(PaymentStatusFfi_Paid) _then) = _$PaymentStatusFfi_PaidCopyWithImpl;
@override @useResult
$Res call({
 BigInt field0
});




}
/// @nodoc
class _$PaymentStatusFfi_PaidCopyWithImpl<$Res>
    implements $PaymentStatusFfi_PaidCopyWith<$Res> {
  _$PaymentStatusFfi_PaidCopyWithImpl(this._self, this._then);

  final PaymentStatusFfi_Paid _self;
  final $Res Function(PaymentStatusFfi_Paid) _then;

/// Create a copy of PaymentStatusFfi
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(PaymentStatusFfi_Paid(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class PaymentStatusFfi_Rejected extends PaymentStatusFfi {
  const PaymentStatusFfi_Rejected(this.field0): super._();
  

@override final  BigInt field0;

/// Create a copy of PaymentStatusFfi
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$PaymentStatusFfi_RejectedCopyWith<PaymentStatusFfi_Rejected> get copyWith => _$PaymentStatusFfi_RejectedCopyWithImpl<PaymentStatusFfi_Rejected>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is PaymentStatusFfi_Rejected&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'PaymentStatusFfi.rejected(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $PaymentStatusFfi_RejectedCopyWith<$Res> implements $PaymentStatusFfiCopyWith<$Res> {
  factory $PaymentStatusFfi_RejectedCopyWith(PaymentStatusFfi_Rejected value, $Res Function(PaymentStatusFfi_Rejected) _then) = _$PaymentStatusFfi_RejectedCopyWithImpl;
@override @useResult
$Res call({
 BigInt field0
});




}
/// @nodoc
class _$PaymentStatusFfi_RejectedCopyWithImpl<$Res>
    implements $PaymentStatusFfi_RejectedCopyWith<$Res> {
  _$PaymentStatusFfi_RejectedCopyWithImpl(this._self, this._then);

  final PaymentStatusFfi_Rejected _self;
  final $Res Function(PaymentStatusFfi_Rejected) _then;

/// Create a copy of PaymentStatusFfi
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(PaymentStatusFfi_Rejected(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class PaymentStatusFfi_Expired extends PaymentStatusFfi {
  const PaymentStatusFfi_Expired(this.field0): super._();
  

@override final  BigInt field0;

/// Create a copy of PaymentStatusFfi
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$PaymentStatusFfi_ExpiredCopyWith<PaymentStatusFfi_Expired> get copyWith => _$PaymentStatusFfi_ExpiredCopyWithImpl<PaymentStatusFfi_Expired>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is PaymentStatusFfi_Expired&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'PaymentStatusFfi.expired(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $PaymentStatusFfi_ExpiredCopyWith<$Res> implements $PaymentStatusFfiCopyWith<$Res> {
  factory $PaymentStatusFfi_ExpiredCopyWith(PaymentStatusFfi_Expired value, $Res Function(PaymentStatusFfi_Expired) _then) = _$PaymentStatusFfi_ExpiredCopyWithImpl;
@override @useResult
$Res call({
 BigInt field0
});




}
/// @nodoc
class _$PaymentStatusFfi_ExpiredCopyWithImpl<$Res>
    implements $PaymentStatusFfi_ExpiredCopyWith<$Res> {
  _$PaymentStatusFfi_ExpiredCopyWithImpl(this._self, this._then);

  final PaymentStatusFfi_Expired _self;
  final $Res Function(PaymentStatusFfi_Expired) _then;

/// Create a copy of PaymentStatusFfi
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(PaymentStatusFfi_Expired(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

// dart format on

// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'company.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$CompanySignatoryStatusFfi {

 BigInt get ts;
/// Create a copy of CompanySignatoryStatusFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CompanySignatoryStatusFfiCopyWith<CompanySignatoryStatusFfi> get copyWith => _$CompanySignatoryStatusFfiCopyWithImpl<CompanySignatoryStatusFfi>(this as CompanySignatoryStatusFfi, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CompanySignatoryStatusFfi&&(identical(other.ts, ts) || other.ts == ts));
}


@override
int get hashCode => Object.hash(runtimeType,ts);

@override
String toString() {
  return 'CompanySignatoryStatusFfi(ts: $ts)';
}


}

/// @nodoc
abstract mixin class $CompanySignatoryStatusFfiCopyWith<$Res>  {
  factory $CompanySignatoryStatusFfiCopyWith(CompanySignatoryStatusFfi value, $Res Function(CompanySignatoryStatusFfi) _then) = _$CompanySignatoryStatusFfiCopyWithImpl;
@useResult
$Res call({
 BigInt ts
});




}
/// @nodoc
class _$CompanySignatoryStatusFfiCopyWithImpl<$Res>
    implements $CompanySignatoryStatusFfiCopyWith<$Res> {
  _$CompanySignatoryStatusFfiCopyWithImpl(this._self, this._then);

  final CompanySignatoryStatusFfi _self;
  final $Res Function(CompanySignatoryStatusFfi) _then;

/// Create a copy of CompanySignatoryStatusFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') @override $Res call({Object? ts = null,}) {
  return _then(_self.copyWith(
ts: null == ts ? _self.ts : ts // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}

}


/// Adds pattern-matching-related methods to [CompanySignatoryStatusFfi].
extension CompanySignatoryStatusFfiPatterns on CompanySignatoryStatusFfi {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( CompanySignatoryStatusFfi_Invited value)?  invited,TResult Function( CompanySignatoryStatusFfi_InviteAccepted value)?  inviteAccepted,TResult Function( CompanySignatoryStatusFfi_InviteRejected value)?  inviteRejected,TResult Function( CompanySignatoryStatusFfi_InviteAcceptedIdentityProven value)?  inviteAcceptedIdentityProven,TResult Function( CompanySignatoryStatusFfi_Removed value)?  removed,required TResult orElse(),}){
final _that = this;
switch (_that) {
case CompanySignatoryStatusFfi_Invited() when invited != null:
return invited(_that);case CompanySignatoryStatusFfi_InviteAccepted() when inviteAccepted != null:
return inviteAccepted(_that);case CompanySignatoryStatusFfi_InviteRejected() when inviteRejected != null:
return inviteRejected(_that);case CompanySignatoryStatusFfi_InviteAcceptedIdentityProven() when inviteAcceptedIdentityProven != null:
return inviteAcceptedIdentityProven(_that);case CompanySignatoryStatusFfi_Removed() when removed != null:
return removed(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( CompanySignatoryStatusFfi_Invited value)  invited,required TResult Function( CompanySignatoryStatusFfi_InviteAccepted value)  inviteAccepted,required TResult Function( CompanySignatoryStatusFfi_InviteRejected value)  inviteRejected,required TResult Function( CompanySignatoryStatusFfi_InviteAcceptedIdentityProven value)  inviteAcceptedIdentityProven,required TResult Function( CompanySignatoryStatusFfi_Removed value)  removed,}){
final _that = this;
switch (_that) {
case CompanySignatoryStatusFfi_Invited():
return invited(_that);case CompanySignatoryStatusFfi_InviteAccepted():
return inviteAccepted(_that);case CompanySignatoryStatusFfi_InviteRejected():
return inviteRejected(_that);case CompanySignatoryStatusFfi_InviteAcceptedIdentityProven():
return inviteAcceptedIdentityProven(_that);case CompanySignatoryStatusFfi_Removed():
return removed(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( CompanySignatoryStatusFfi_Invited value)?  invited,TResult? Function( CompanySignatoryStatusFfi_InviteAccepted value)?  inviteAccepted,TResult? Function( CompanySignatoryStatusFfi_InviteRejected value)?  inviteRejected,TResult? Function( CompanySignatoryStatusFfi_InviteAcceptedIdentityProven value)?  inviteAcceptedIdentityProven,TResult? Function( CompanySignatoryStatusFfi_Removed value)?  removed,}){
final _that = this;
switch (_that) {
case CompanySignatoryStatusFfi_Invited() when invited != null:
return invited(_that);case CompanySignatoryStatusFfi_InviteAccepted() when inviteAccepted != null:
return inviteAccepted(_that);case CompanySignatoryStatusFfi_InviteRejected() when inviteRejected != null:
return inviteRejected(_that);case CompanySignatoryStatusFfi_InviteAcceptedIdentityProven() when inviteAcceptedIdentityProven != null:
return inviteAcceptedIdentityProven(_that);case CompanySignatoryStatusFfi_Removed() when removed != null:
return removed(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( BigInt ts,  String inviter)?  invited,TResult Function( BigInt ts)?  inviteAccepted,TResult Function( BigInt ts)?  inviteRejected,TResult Function( BigInt ts,  IdentityEmailConfirmationFfi confirmation)?  inviteAcceptedIdentityProven,TResult Function( BigInt ts,  String remover)?  removed,required TResult orElse(),}) {final _that = this;
switch (_that) {
case CompanySignatoryStatusFfi_Invited() when invited != null:
return invited(_that.ts,_that.inviter);case CompanySignatoryStatusFfi_InviteAccepted() when inviteAccepted != null:
return inviteAccepted(_that.ts);case CompanySignatoryStatusFfi_InviteRejected() when inviteRejected != null:
return inviteRejected(_that.ts);case CompanySignatoryStatusFfi_InviteAcceptedIdentityProven() when inviteAcceptedIdentityProven != null:
return inviteAcceptedIdentityProven(_that.ts,_that.confirmation);case CompanySignatoryStatusFfi_Removed() when removed != null:
return removed(_that.ts,_that.remover);case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( BigInt ts,  String inviter)  invited,required TResult Function( BigInt ts)  inviteAccepted,required TResult Function( BigInt ts)  inviteRejected,required TResult Function( BigInt ts,  IdentityEmailConfirmationFfi confirmation)  inviteAcceptedIdentityProven,required TResult Function( BigInt ts,  String remover)  removed,}) {final _that = this;
switch (_that) {
case CompanySignatoryStatusFfi_Invited():
return invited(_that.ts,_that.inviter);case CompanySignatoryStatusFfi_InviteAccepted():
return inviteAccepted(_that.ts);case CompanySignatoryStatusFfi_InviteRejected():
return inviteRejected(_that.ts);case CompanySignatoryStatusFfi_InviteAcceptedIdentityProven():
return inviteAcceptedIdentityProven(_that.ts,_that.confirmation);case CompanySignatoryStatusFfi_Removed():
return removed(_that.ts,_that.remover);}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( BigInt ts,  String inviter)?  invited,TResult? Function( BigInt ts)?  inviteAccepted,TResult? Function( BigInt ts)?  inviteRejected,TResult? Function( BigInt ts,  IdentityEmailConfirmationFfi confirmation)?  inviteAcceptedIdentityProven,TResult? Function( BigInt ts,  String remover)?  removed,}) {final _that = this;
switch (_that) {
case CompanySignatoryStatusFfi_Invited() when invited != null:
return invited(_that.ts,_that.inviter);case CompanySignatoryStatusFfi_InviteAccepted() when inviteAccepted != null:
return inviteAccepted(_that.ts);case CompanySignatoryStatusFfi_InviteRejected() when inviteRejected != null:
return inviteRejected(_that.ts);case CompanySignatoryStatusFfi_InviteAcceptedIdentityProven() when inviteAcceptedIdentityProven != null:
return inviteAcceptedIdentityProven(_that.ts,_that.confirmation);case CompanySignatoryStatusFfi_Removed() when removed != null:
return removed(_that.ts,_that.remover);case _:
  return null;

}
}

}

/// @nodoc


class CompanySignatoryStatusFfi_Invited extends CompanySignatoryStatusFfi {
  const CompanySignatoryStatusFfi_Invited({required this.ts, required this.inviter}): super._();
  

@override final  BigInt ts;
 final  String inviter;

/// Create a copy of CompanySignatoryStatusFfi
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CompanySignatoryStatusFfi_InvitedCopyWith<CompanySignatoryStatusFfi_Invited> get copyWith => _$CompanySignatoryStatusFfi_InvitedCopyWithImpl<CompanySignatoryStatusFfi_Invited>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CompanySignatoryStatusFfi_Invited&&(identical(other.ts, ts) || other.ts == ts)&&(identical(other.inviter, inviter) || other.inviter == inviter));
}


@override
int get hashCode => Object.hash(runtimeType,ts,inviter);

@override
String toString() {
  return 'CompanySignatoryStatusFfi.invited(ts: $ts, inviter: $inviter)';
}


}

/// @nodoc
abstract mixin class $CompanySignatoryStatusFfi_InvitedCopyWith<$Res> implements $CompanySignatoryStatusFfiCopyWith<$Res> {
  factory $CompanySignatoryStatusFfi_InvitedCopyWith(CompanySignatoryStatusFfi_Invited value, $Res Function(CompanySignatoryStatusFfi_Invited) _then) = _$CompanySignatoryStatusFfi_InvitedCopyWithImpl;
@override @useResult
$Res call({
 BigInt ts, String inviter
});




}
/// @nodoc
class _$CompanySignatoryStatusFfi_InvitedCopyWithImpl<$Res>
    implements $CompanySignatoryStatusFfi_InvitedCopyWith<$Res> {
  _$CompanySignatoryStatusFfi_InvitedCopyWithImpl(this._self, this._then);

  final CompanySignatoryStatusFfi_Invited _self;
  final $Res Function(CompanySignatoryStatusFfi_Invited) _then;

/// Create a copy of CompanySignatoryStatusFfi
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? ts = null,Object? inviter = null,}) {
  return _then(CompanySignatoryStatusFfi_Invited(
ts: null == ts ? _self.ts : ts // ignore: cast_nullable_to_non_nullable
as BigInt,inviter: null == inviter ? _self.inviter : inviter // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class CompanySignatoryStatusFfi_InviteAccepted extends CompanySignatoryStatusFfi {
  const CompanySignatoryStatusFfi_InviteAccepted({required this.ts}): super._();
  

@override final  BigInt ts;

/// Create a copy of CompanySignatoryStatusFfi
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CompanySignatoryStatusFfi_InviteAcceptedCopyWith<CompanySignatoryStatusFfi_InviteAccepted> get copyWith => _$CompanySignatoryStatusFfi_InviteAcceptedCopyWithImpl<CompanySignatoryStatusFfi_InviteAccepted>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CompanySignatoryStatusFfi_InviteAccepted&&(identical(other.ts, ts) || other.ts == ts));
}


@override
int get hashCode => Object.hash(runtimeType,ts);

@override
String toString() {
  return 'CompanySignatoryStatusFfi.inviteAccepted(ts: $ts)';
}


}

/// @nodoc
abstract mixin class $CompanySignatoryStatusFfi_InviteAcceptedCopyWith<$Res> implements $CompanySignatoryStatusFfiCopyWith<$Res> {
  factory $CompanySignatoryStatusFfi_InviteAcceptedCopyWith(CompanySignatoryStatusFfi_InviteAccepted value, $Res Function(CompanySignatoryStatusFfi_InviteAccepted) _then) = _$CompanySignatoryStatusFfi_InviteAcceptedCopyWithImpl;
@override @useResult
$Res call({
 BigInt ts
});




}
/// @nodoc
class _$CompanySignatoryStatusFfi_InviteAcceptedCopyWithImpl<$Res>
    implements $CompanySignatoryStatusFfi_InviteAcceptedCopyWith<$Res> {
  _$CompanySignatoryStatusFfi_InviteAcceptedCopyWithImpl(this._self, this._then);

  final CompanySignatoryStatusFfi_InviteAccepted _self;
  final $Res Function(CompanySignatoryStatusFfi_InviteAccepted) _then;

/// Create a copy of CompanySignatoryStatusFfi
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? ts = null,}) {
  return _then(CompanySignatoryStatusFfi_InviteAccepted(
ts: null == ts ? _self.ts : ts // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class CompanySignatoryStatusFfi_InviteRejected extends CompanySignatoryStatusFfi {
  const CompanySignatoryStatusFfi_InviteRejected({required this.ts}): super._();
  

@override final  BigInt ts;

/// Create a copy of CompanySignatoryStatusFfi
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CompanySignatoryStatusFfi_InviteRejectedCopyWith<CompanySignatoryStatusFfi_InviteRejected> get copyWith => _$CompanySignatoryStatusFfi_InviteRejectedCopyWithImpl<CompanySignatoryStatusFfi_InviteRejected>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CompanySignatoryStatusFfi_InviteRejected&&(identical(other.ts, ts) || other.ts == ts));
}


@override
int get hashCode => Object.hash(runtimeType,ts);

@override
String toString() {
  return 'CompanySignatoryStatusFfi.inviteRejected(ts: $ts)';
}


}

/// @nodoc
abstract mixin class $CompanySignatoryStatusFfi_InviteRejectedCopyWith<$Res> implements $CompanySignatoryStatusFfiCopyWith<$Res> {
  factory $CompanySignatoryStatusFfi_InviteRejectedCopyWith(CompanySignatoryStatusFfi_InviteRejected value, $Res Function(CompanySignatoryStatusFfi_InviteRejected) _then) = _$CompanySignatoryStatusFfi_InviteRejectedCopyWithImpl;
@override @useResult
$Res call({
 BigInt ts
});




}
/// @nodoc
class _$CompanySignatoryStatusFfi_InviteRejectedCopyWithImpl<$Res>
    implements $CompanySignatoryStatusFfi_InviteRejectedCopyWith<$Res> {
  _$CompanySignatoryStatusFfi_InviteRejectedCopyWithImpl(this._self, this._then);

  final CompanySignatoryStatusFfi_InviteRejected _self;
  final $Res Function(CompanySignatoryStatusFfi_InviteRejected) _then;

/// Create a copy of CompanySignatoryStatusFfi
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? ts = null,}) {
  return _then(CompanySignatoryStatusFfi_InviteRejected(
ts: null == ts ? _self.ts : ts // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class CompanySignatoryStatusFfi_InviteAcceptedIdentityProven extends CompanySignatoryStatusFfi {
  const CompanySignatoryStatusFfi_InviteAcceptedIdentityProven({required this.ts, required this.confirmation}): super._();
  

@override final  BigInt ts;
 final  IdentityEmailConfirmationFfi confirmation;

/// Create a copy of CompanySignatoryStatusFfi
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CompanySignatoryStatusFfi_InviteAcceptedIdentityProvenCopyWith<CompanySignatoryStatusFfi_InviteAcceptedIdentityProven> get copyWith => _$CompanySignatoryStatusFfi_InviteAcceptedIdentityProvenCopyWithImpl<CompanySignatoryStatusFfi_InviteAcceptedIdentityProven>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CompanySignatoryStatusFfi_InviteAcceptedIdentityProven&&(identical(other.ts, ts) || other.ts == ts)&&(identical(other.confirmation, confirmation) || other.confirmation == confirmation));
}


@override
int get hashCode => Object.hash(runtimeType,ts,confirmation);

@override
String toString() {
  return 'CompanySignatoryStatusFfi.inviteAcceptedIdentityProven(ts: $ts, confirmation: $confirmation)';
}


}

/// @nodoc
abstract mixin class $CompanySignatoryStatusFfi_InviteAcceptedIdentityProvenCopyWith<$Res> implements $CompanySignatoryStatusFfiCopyWith<$Res> {
  factory $CompanySignatoryStatusFfi_InviteAcceptedIdentityProvenCopyWith(CompanySignatoryStatusFfi_InviteAcceptedIdentityProven value, $Res Function(CompanySignatoryStatusFfi_InviteAcceptedIdentityProven) _then) = _$CompanySignatoryStatusFfi_InviteAcceptedIdentityProvenCopyWithImpl;
@override @useResult
$Res call({
 BigInt ts, IdentityEmailConfirmationFfi confirmation
});




}
/// @nodoc
class _$CompanySignatoryStatusFfi_InviteAcceptedIdentityProvenCopyWithImpl<$Res>
    implements $CompanySignatoryStatusFfi_InviteAcceptedIdentityProvenCopyWith<$Res> {
  _$CompanySignatoryStatusFfi_InviteAcceptedIdentityProvenCopyWithImpl(this._self, this._then);

  final CompanySignatoryStatusFfi_InviteAcceptedIdentityProven _self;
  final $Res Function(CompanySignatoryStatusFfi_InviteAcceptedIdentityProven) _then;

/// Create a copy of CompanySignatoryStatusFfi
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? ts = null,Object? confirmation = null,}) {
  return _then(CompanySignatoryStatusFfi_InviteAcceptedIdentityProven(
ts: null == ts ? _self.ts : ts // ignore: cast_nullable_to_non_nullable
as BigInt,confirmation: null == confirmation ? _self.confirmation : confirmation // ignore: cast_nullable_to_non_nullable
as IdentityEmailConfirmationFfi,
  ));
}


}

/// @nodoc


class CompanySignatoryStatusFfi_Removed extends CompanySignatoryStatusFfi {
  const CompanySignatoryStatusFfi_Removed({required this.ts, required this.remover}): super._();
  

@override final  BigInt ts;
 final  String remover;

/// Create a copy of CompanySignatoryStatusFfi
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$CompanySignatoryStatusFfi_RemovedCopyWith<CompanySignatoryStatusFfi_Removed> get copyWith => _$CompanySignatoryStatusFfi_RemovedCopyWithImpl<CompanySignatoryStatusFfi_Removed>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is CompanySignatoryStatusFfi_Removed&&(identical(other.ts, ts) || other.ts == ts)&&(identical(other.remover, remover) || other.remover == remover));
}


@override
int get hashCode => Object.hash(runtimeType,ts,remover);

@override
String toString() {
  return 'CompanySignatoryStatusFfi.removed(ts: $ts, remover: $remover)';
}


}

/// @nodoc
abstract mixin class $CompanySignatoryStatusFfi_RemovedCopyWith<$Res> implements $CompanySignatoryStatusFfiCopyWith<$Res> {
  factory $CompanySignatoryStatusFfi_RemovedCopyWith(CompanySignatoryStatusFfi_Removed value, $Res Function(CompanySignatoryStatusFfi_Removed) _then) = _$CompanySignatoryStatusFfi_RemovedCopyWithImpl;
@override @useResult
$Res call({
 BigInt ts, String remover
});




}
/// @nodoc
class _$CompanySignatoryStatusFfi_RemovedCopyWithImpl<$Res>
    implements $CompanySignatoryStatusFfi_RemovedCopyWith<$Res> {
  _$CompanySignatoryStatusFfi_RemovedCopyWithImpl(this._self, this._then);

  final CompanySignatoryStatusFfi_Removed _self;
  final $Res Function(CompanySignatoryStatusFfi_Removed) _then;

/// Create a copy of CompanySignatoryStatusFfi
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? ts = null,Object? remover = null,}) {
  return _then(CompanySignatoryStatusFfi_Removed(
ts: null == ts ? _self.ts : ts // ignore: cast_nullable_to_non_nullable
as BigInt,remover: null == remover ? _self.remover : remover // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

// dart format on

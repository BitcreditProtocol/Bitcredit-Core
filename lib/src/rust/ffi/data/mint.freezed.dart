// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'mint.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$MintRequestStatusFfi {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MintRequestStatusFfi);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'MintRequestStatusFfi()';
}


}

/// @nodoc
class $MintRequestStatusFfiCopyWith<$Res>  {
$MintRequestStatusFfiCopyWith(MintRequestStatusFfi _, $Res Function(MintRequestStatusFfi) __);
}


/// Adds pattern-matching-related methods to [MintRequestStatusFfi].
extension MintRequestStatusFfiPatterns on MintRequestStatusFfi {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( MintRequestStatusFfi_Pending value)?  pending,TResult Function( MintRequestStatusFfi_Denied value)?  denied,TResult Function( MintRequestStatusFfi_Offered value)?  offered,TResult Function( MintRequestStatusFfi_Accepted value)?  accepted,TResult Function( MintRequestStatusFfi_MintingEnabled value)?  mintingEnabled,TResult Function( MintRequestStatusFfi_Rejected value)?  rejected,TResult Function( MintRequestStatusFfi_Cancelled value)?  cancelled,TResult Function( MintRequestStatusFfi_Expired value)?  expired,required TResult orElse(),}){
final _that = this;
switch (_that) {
case MintRequestStatusFfi_Pending() when pending != null:
return pending(_that);case MintRequestStatusFfi_Denied() when denied != null:
return denied(_that);case MintRequestStatusFfi_Offered() when offered != null:
return offered(_that);case MintRequestStatusFfi_Accepted() when accepted != null:
return accepted(_that);case MintRequestStatusFfi_MintingEnabled() when mintingEnabled != null:
return mintingEnabled(_that);case MintRequestStatusFfi_Rejected() when rejected != null:
return rejected(_that);case MintRequestStatusFfi_Cancelled() when cancelled != null:
return cancelled(_that);case MintRequestStatusFfi_Expired() when expired != null:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( MintRequestStatusFfi_Pending value)  pending,required TResult Function( MintRequestStatusFfi_Denied value)  denied,required TResult Function( MintRequestStatusFfi_Offered value)  offered,required TResult Function( MintRequestStatusFfi_Accepted value)  accepted,required TResult Function( MintRequestStatusFfi_MintingEnabled value)  mintingEnabled,required TResult Function( MintRequestStatusFfi_Rejected value)  rejected,required TResult Function( MintRequestStatusFfi_Cancelled value)  cancelled,required TResult Function( MintRequestStatusFfi_Expired value)  expired,}){
final _that = this;
switch (_that) {
case MintRequestStatusFfi_Pending():
return pending(_that);case MintRequestStatusFfi_Denied():
return denied(_that);case MintRequestStatusFfi_Offered():
return offered(_that);case MintRequestStatusFfi_Accepted():
return accepted(_that);case MintRequestStatusFfi_MintingEnabled():
return mintingEnabled(_that);case MintRequestStatusFfi_Rejected():
return rejected(_that);case MintRequestStatusFfi_Cancelled():
return cancelled(_that);case MintRequestStatusFfi_Expired():
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( MintRequestStatusFfi_Pending value)?  pending,TResult? Function( MintRequestStatusFfi_Denied value)?  denied,TResult? Function( MintRequestStatusFfi_Offered value)?  offered,TResult? Function( MintRequestStatusFfi_Accepted value)?  accepted,TResult? Function( MintRequestStatusFfi_MintingEnabled value)?  mintingEnabled,TResult? Function( MintRequestStatusFfi_Rejected value)?  rejected,TResult? Function( MintRequestStatusFfi_Cancelled value)?  cancelled,TResult? Function( MintRequestStatusFfi_Expired value)?  expired,}){
final _that = this;
switch (_that) {
case MintRequestStatusFfi_Pending() when pending != null:
return pending(_that);case MintRequestStatusFfi_Denied() when denied != null:
return denied(_that);case MintRequestStatusFfi_Offered() when offered != null:
return offered(_that);case MintRequestStatusFfi_Accepted() when accepted != null:
return accepted(_that);case MintRequestStatusFfi_MintingEnabled() when mintingEnabled != null:
return mintingEnabled(_that);case MintRequestStatusFfi_Rejected() when rejected != null:
return rejected(_that);case MintRequestStatusFfi_Cancelled() when cancelled != null:
return cancelled(_that);case MintRequestStatusFfi_Expired() when expired != null:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function()?  pending,TResult Function( BigInt timestamp)?  denied,TResult Function()?  offered,TResult Function()?  accepted,TResult Function()?  mintingEnabled,TResult Function( BigInt timestamp)?  rejected,TResult Function( BigInt timestamp)?  cancelled,TResult Function( BigInt timestamp)?  expired,required TResult orElse(),}) {final _that = this;
switch (_that) {
case MintRequestStatusFfi_Pending() when pending != null:
return pending();case MintRequestStatusFfi_Denied() when denied != null:
return denied(_that.timestamp);case MintRequestStatusFfi_Offered() when offered != null:
return offered();case MintRequestStatusFfi_Accepted() when accepted != null:
return accepted();case MintRequestStatusFfi_MintingEnabled() when mintingEnabled != null:
return mintingEnabled();case MintRequestStatusFfi_Rejected() when rejected != null:
return rejected(_that.timestamp);case MintRequestStatusFfi_Cancelled() when cancelled != null:
return cancelled(_that.timestamp);case MintRequestStatusFfi_Expired() when expired != null:
return expired(_that.timestamp);case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function()  pending,required TResult Function( BigInt timestamp)  denied,required TResult Function()  offered,required TResult Function()  accepted,required TResult Function()  mintingEnabled,required TResult Function( BigInt timestamp)  rejected,required TResult Function( BigInt timestamp)  cancelled,required TResult Function( BigInt timestamp)  expired,}) {final _that = this;
switch (_that) {
case MintRequestStatusFfi_Pending():
return pending();case MintRequestStatusFfi_Denied():
return denied(_that.timestamp);case MintRequestStatusFfi_Offered():
return offered();case MintRequestStatusFfi_Accepted():
return accepted();case MintRequestStatusFfi_MintingEnabled():
return mintingEnabled();case MintRequestStatusFfi_Rejected():
return rejected(_that.timestamp);case MintRequestStatusFfi_Cancelled():
return cancelled(_that.timestamp);case MintRequestStatusFfi_Expired():
return expired(_that.timestamp);}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function()?  pending,TResult? Function( BigInt timestamp)?  denied,TResult? Function()?  offered,TResult? Function()?  accepted,TResult? Function()?  mintingEnabled,TResult? Function( BigInt timestamp)?  rejected,TResult? Function( BigInt timestamp)?  cancelled,TResult? Function( BigInt timestamp)?  expired,}) {final _that = this;
switch (_that) {
case MintRequestStatusFfi_Pending() when pending != null:
return pending();case MintRequestStatusFfi_Denied() when denied != null:
return denied(_that.timestamp);case MintRequestStatusFfi_Offered() when offered != null:
return offered();case MintRequestStatusFfi_Accepted() when accepted != null:
return accepted();case MintRequestStatusFfi_MintingEnabled() when mintingEnabled != null:
return mintingEnabled();case MintRequestStatusFfi_Rejected() when rejected != null:
return rejected(_that.timestamp);case MintRequestStatusFfi_Cancelled() when cancelled != null:
return cancelled(_that.timestamp);case MintRequestStatusFfi_Expired() when expired != null:
return expired(_that.timestamp);case _:
  return null;

}
}

}

/// @nodoc


class MintRequestStatusFfi_Pending extends MintRequestStatusFfi {
  const MintRequestStatusFfi_Pending(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MintRequestStatusFfi_Pending);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'MintRequestStatusFfi.pending()';
}


}




/// @nodoc


class MintRequestStatusFfi_Denied extends MintRequestStatusFfi {
  const MintRequestStatusFfi_Denied({required this.timestamp}): super._();
  

 final  BigInt timestamp;

/// Create a copy of MintRequestStatusFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$MintRequestStatusFfi_DeniedCopyWith<MintRequestStatusFfi_Denied> get copyWith => _$MintRequestStatusFfi_DeniedCopyWithImpl<MintRequestStatusFfi_Denied>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MintRequestStatusFfi_Denied&&(identical(other.timestamp, timestamp) || other.timestamp == timestamp));
}


@override
int get hashCode => Object.hash(runtimeType,timestamp);

@override
String toString() {
  return 'MintRequestStatusFfi.denied(timestamp: $timestamp)';
}


}

/// @nodoc
abstract mixin class $MintRequestStatusFfi_DeniedCopyWith<$Res> implements $MintRequestStatusFfiCopyWith<$Res> {
  factory $MintRequestStatusFfi_DeniedCopyWith(MintRequestStatusFfi_Denied value, $Res Function(MintRequestStatusFfi_Denied) _then) = _$MintRequestStatusFfi_DeniedCopyWithImpl;
@useResult
$Res call({
 BigInt timestamp
});




}
/// @nodoc
class _$MintRequestStatusFfi_DeniedCopyWithImpl<$Res>
    implements $MintRequestStatusFfi_DeniedCopyWith<$Res> {
  _$MintRequestStatusFfi_DeniedCopyWithImpl(this._self, this._then);

  final MintRequestStatusFfi_Denied _self;
  final $Res Function(MintRequestStatusFfi_Denied) _then;

/// Create a copy of MintRequestStatusFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? timestamp = null,}) {
  return _then(MintRequestStatusFfi_Denied(
timestamp: null == timestamp ? _self.timestamp : timestamp // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class MintRequestStatusFfi_Offered extends MintRequestStatusFfi {
  const MintRequestStatusFfi_Offered(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MintRequestStatusFfi_Offered);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'MintRequestStatusFfi.offered()';
}


}




/// @nodoc


class MintRequestStatusFfi_Accepted extends MintRequestStatusFfi {
  const MintRequestStatusFfi_Accepted(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MintRequestStatusFfi_Accepted);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'MintRequestStatusFfi.accepted()';
}


}




/// @nodoc


class MintRequestStatusFfi_MintingEnabled extends MintRequestStatusFfi {
  const MintRequestStatusFfi_MintingEnabled(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MintRequestStatusFfi_MintingEnabled);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'MintRequestStatusFfi.mintingEnabled()';
}


}




/// @nodoc


class MintRequestStatusFfi_Rejected extends MintRequestStatusFfi {
  const MintRequestStatusFfi_Rejected({required this.timestamp}): super._();
  

 final  BigInt timestamp;

/// Create a copy of MintRequestStatusFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$MintRequestStatusFfi_RejectedCopyWith<MintRequestStatusFfi_Rejected> get copyWith => _$MintRequestStatusFfi_RejectedCopyWithImpl<MintRequestStatusFfi_Rejected>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MintRequestStatusFfi_Rejected&&(identical(other.timestamp, timestamp) || other.timestamp == timestamp));
}


@override
int get hashCode => Object.hash(runtimeType,timestamp);

@override
String toString() {
  return 'MintRequestStatusFfi.rejected(timestamp: $timestamp)';
}


}

/// @nodoc
abstract mixin class $MintRequestStatusFfi_RejectedCopyWith<$Res> implements $MintRequestStatusFfiCopyWith<$Res> {
  factory $MintRequestStatusFfi_RejectedCopyWith(MintRequestStatusFfi_Rejected value, $Res Function(MintRequestStatusFfi_Rejected) _then) = _$MintRequestStatusFfi_RejectedCopyWithImpl;
@useResult
$Res call({
 BigInt timestamp
});




}
/// @nodoc
class _$MintRequestStatusFfi_RejectedCopyWithImpl<$Res>
    implements $MintRequestStatusFfi_RejectedCopyWith<$Res> {
  _$MintRequestStatusFfi_RejectedCopyWithImpl(this._self, this._then);

  final MintRequestStatusFfi_Rejected _self;
  final $Res Function(MintRequestStatusFfi_Rejected) _then;

/// Create a copy of MintRequestStatusFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? timestamp = null,}) {
  return _then(MintRequestStatusFfi_Rejected(
timestamp: null == timestamp ? _self.timestamp : timestamp // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class MintRequestStatusFfi_Cancelled extends MintRequestStatusFfi {
  const MintRequestStatusFfi_Cancelled({required this.timestamp}): super._();
  

 final  BigInt timestamp;

/// Create a copy of MintRequestStatusFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$MintRequestStatusFfi_CancelledCopyWith<MintRequestStatusFfi_Cancelled> get copyWith => _$MintRequestStatusFfi_CancelledCopyWithImpl<MintRequestStatusFfi_Cancelled>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MintRequestStatusFfi_Cancelled&&(identical(other.timestamp, timestamp) || other.timestamp == timestamp));
}


@override
int get hashCode => Object.hash(runtimeType,timestamp);

@override
String toString() {
  return 'MintRequestStatusFfi.cancelled(timestamp: $timestamp)';
}


}

/// @nodoc
abstract mixin class $MintRequestStatusFfi_CancelledCopyWith<$Res> implements $MintRequestStatusFfiCopyWith<$Res> {
  factory $MintRequestStatusFfi_CancelledCopyWith(MintRequestStatusFfi_Cancelled value, $Res Function(MintRequestStatusFfi_Cancelled) _then) = _$MintRequestStatusFfi_CancelledCopyWithImpl;
@useResult
$Res call({
 BigInt timestamp
});




}
/// @nodoc
class _$MintRequestStatusFfi_CancelledCopyWithImpl<$Res>
    implements $MintRequestStatusFfi_CancelledCopyWith<$Res> {
  _$MintRequestStatusFfi_CancelledCopyWithImpl(this._self, this._then);

  final MintRequestStatusFfi_Cancelled _self;
  final $Res Function(MintRequestStatusFfi_Cancelled) _then;

/// Create a copy of MintRequestStatusFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? timestamp = null,}) {
  return _then(MintRequestStatusFfi_Cancelled(
timestamp: null == timestamp ? _self.timestamp : timestamp // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

/// @nodoc


class MintRequestStatusFfi_Expired extends MintRequestStatusFfi {
  const MintRequestStatusFfi_Expired({required this.timestamp}): super._();
  

 final  BigInt timestamp;

/// Create a copy of MintRequestStatusFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$MintRequestStatusFfi_ExpiredCopyWith<MintRequestStatusFfi_Expired> get copyWith => _$MintRequestStatusFfi_ExpiredCopyWithImpl<MintRequestStatusFfi_Expired>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MintRequestStatusFfi_Expired&&(identical(other.timestamp, timestamp) || other.timestamp == timestamp));
}


@override
int get hashCode => Object.hash(runtimeType,timestamp);

@override
String toString() {
  return 'MintRequestStatusFfi.expired(timestamp: $timestamp)';
}


}

/// @nodoc
abstract mixin class $MintRequestStatusFfi_ExpiredCopyWith<$Res> implements $MintRequestStatusFfiCopyWith<$Res> {
  factory $MintRequestStatusFfi_ExpiredCopyWith(MintRequestStatusFfi_Expired value, $Res Function(MintRequestStatusFfi_Expired) _then) = _$MintRequestStatusFfi_ExpiredCopyWithImpl;
@useResult
$Res call({
 BigInt timestamp
});




}
/// @nodoc
class _$MintRequestStatusFfi_ExpiredCopyWithImpl<$Res>
    implements $MintRequestStatusFfi_ExpiredCopyWith<$Res> {
  _$MintRequestStatusFfi_ExpiredCopyWithImpl(this._self, this._then);

  final MintRequestStatusFfi_Expired _self;
  final $Res Function(MintRequestStatusFfi_Expired) _then;

/// Create a copy of MintRequestStatusFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? timestamp = null,}) {
  return _then(MintRequestStatusFfi_Expired(
timestamp: null == timestamp ? _self.timestamp : timestamp // ignore: cast_nullable_to_non_nullable
as BigInt,
  ));
}


}

// dart format on

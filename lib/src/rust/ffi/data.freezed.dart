// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'data.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$EditOptionalFieldModeFfi {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is EditOptionalFieldModeFfi);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'EditOptionalFieldModeFfi()';
}


}

/// @nodoc
class $EditOptionalFieldModeFfiCopyWith<$Res>  {
$EditOptionalFieldModeFfiCopyWith(EditOptionalFieldModeFfi _, $Res Function(EditOptionalFieldModeFfi) __);
}


/// Adds pattern-matching-related methods to [EditOptionalFieldModeFfi].
extension EditOptionalFieldModeFfiPatterns on EditOptionalFieldModeFfi {
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

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( EditOptionalFieldModeFfi_Set value)?  set_,TResult Function( EditOptionalFieldModeFfi_Unset value)?  unset,TResult Function( EditOptionalFieldModeFfi_Ignore value)?  ignore,required TResult orElse(),}){
final _that = this;
switch (_that) {
case EditOptionalFieldModeFfi_Set() when set_ != null:
return set_(_that);case EditOptionalFieldModeFfi_Unset() when unset != null:
return unset(_that);case EditOptionalFieldModeFfi_Ignore() when ignore != null:
return ignore(_that);case _:
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

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( EditOptionalFieldModeFfi_Set value)  set_,required TResult Function( EditOptionalFieldModeFfi_Unset value)  unset,required TResult Function( EditOptionalFieldModeFfi_Ignore value)  ignore,}){
final _that = this;
switch (_that) {
case EditOptionalFieldModeFfi_Set():
return set_(_that);case EditOptionalFieldModeFfi_Unset():
return unset(_that);case EditOptionalFieldModeFfi_Ignore():
return ignore(_that);}
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

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( EditOptionalFieldModeFfi_Set value)?  set_,TResult? Function( EditOptionalFieldModeFfi_Unset value)?  unset,TResult? Function( EditOptionalFieldModeFfi_Ignore value)?  ignore,}){
final _that = this;
switch (_that) {
case EditOptionalFieldModeFfi_Set() when set_ != null:
return set_(_that);case EditOptionalFieldModeFfi_Unset() when unset != null:
return unset(_that);case EditOptionalFieldModeFfi_Ignore() when ignore != null:
return ignore(_that);case _:
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

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( String field0)?  set_,TResult Function()?  unset,TResult Function()?  ignore,required TResult orElse(),}) {final _that = this;
switch (_that) {
case EditOptionalFieldModeFfi_Set() when set_ != null:
return set_(_that.field0);case EditOptionalFieldModeFfi_Unset() when unset != null:
return unset();case EditOptionalFieldModeFfi_Ignore() when ignore != null:
return ignore();case _:
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

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( String field0)  set_,required TResult Function()  unset,required TResult Function()  ignore,}) {final _that = this;
switch (_that) {
case EditOptionalFieldModeFfi_Set():
return set_(_that.field0);case EditOptionalFieldModeFfi_Unset():
return unset();case EditOptionalFieldModeFfi_Ignore():
return ignore();}
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

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( String field0)?  set_,TResult? Function()?  unset,TResult? Function()?  ignore,}) {final _that = this;
switch (_that) {
case EditOptionalFieldModeFfi_Set() when set_ != null:
return set_(_that.field0);case EditOptionalFieldModeFfi_Unset() when unset != null:
return unset();case EditOptionalFieldModeFfi_Ignore() when ignore != null:
return ignore();case _:
  return null;

}
}

}

/// @nodoc


class EditOptionalFieldModeFfi_Set extends EditOptionalFieldModeFfi {
  const EditOptionalFieldModeFfi_Set(this.field0): super._();
  

 final  String field0;

/// Create a copy of EditOptionalFieldModeFfi
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$EditOptionalFieldModeFfi_SetCopyWith<EditOptionalFieldModeFfi_Set> get copyWith => _$EditOptionalFieldModeFfi_SetCopyWithImpl<EditOptionalFieldModeFfi_Set>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is EditOptionalFieldModeFfi_Set&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'EditOptionalFieldModeFfi.set_(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $EditOptionalFieldModeFfi_SetCopyWith<$Res> implements $EditOptionalFieldModeFfiCopyWith<$Res> {
  factory $EditOptionalFieldModeFfi_SetCopyWith(EditOptionalFieldModeFfi_Set value, $Res Function(EditOptionalFieldModeFfi_Set) _then) = _$EditOptionalFieldModeFfi_SetCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$EditOptionalFieldModeFfi_SetCopyWithImpl<$Res>
    implements $EditOptionalFieldModeFfi_SetCopyWith<$Res> {
  _$EditOptionalFieldModeFfi_SetCopyWithImpl(this._self, this._then);

  final EditOptionalFieldModeFfi_Set _self;
  final $Res Function(EditOptionalFieldModeFfi_Set) _then;

/// Create a copy of EditOptionalFieldModeFfi
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(EditOptionalFieldModeFfi_Set(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class EditOptionalFieldModeFfi_Unset extends EditOptionalFieldModeFfi {
  const EditOptionalFieldModeFfi_Unset(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is EditOptionalFieldModeFfi_Unset);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'EditOptionalFieldModeFfi.unset()';
}


}




/// @nodoc


class EditOptionalFieldModeFfi_Ignore extends EditOptionalFieldModeFfi {
  const EditOptionalFieldModeFfi_Ignore(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is EditOptionalFieldModeFfi_Ignore);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'EditOptionalFieldModeFfi.ignore()';
}


}




// dart format on

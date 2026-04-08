# Basic Parameter Target App

This app implements methods with common parameters such as:

1. **Primitives**
   - `int`, `long`, `short`, `byte`
   - `float`, `double`
   - `boolean`
   - `char`

1. **Strings & Text**
   - `String`
   - `CharSequence`

1. **Arrays**
   - Primitive arrays (e.g., `int[]`, `byte[]`)
   - `String[]`
   - Object arrays

1. **Collections**
   - `List` / `ArrayList`
   - `Map` / `HashMap`
   - `Set` / `HashSet`
   - `LinkedList`

1. **Android-specific / Wrapped Types**
   - `Bundle` (key-value pairs passed between components)
   - `Intent` (used to pass data between activities)
   - `Uri`
   - `Parcelable` / `Serializable` (for passing objects)
   - `Bitmap` (image data)

1. **Nullable / Optional Wrappers**
   - Boxed primitives: `Integer`, `Long`, `Float`, `Double`, `Boolean`

The methods are then called with the according arguments.

This app can be used to test frooky's built-in argument decoders.

import Java from "frida-java-bridge";
import { Decoder } from "../../shared/decoders/baseDecoder";
import { DecodedValue } from "../../shared/decoders/decodedValue";
import { IntentFlagDecoder } from "./android/content/IntentFlagDecoder";

import { Decodable } from "../../shared/decoders/decodable";
import { KeyGenParameterSpecDecoder } from "./android/security/keystore/KeyGenParameterSpecDecoder";
import { IterableDecoder } from "./java/lang/IterableDecoder";
import { MapDecoder } from "./java/util/MapDecoder";
import { JavaFallbackDecoder } from "./javaBasicDecoder";

type DecoderConstructor = { new (decodable: Decodable): Decoder<Java.Wrapper> };

const iterableClasses: string[] = [
  // java.util - Lists
  "java.util.ArrayList",
  "java.util.LinkedList",
  "java.util.Vector",
  "java.util.Stack",
  "java.util.Arrays$ArrayList",
  "java.util.Collections$SingletonList",
  "java.util.Collections$UnmodifiableList",
  "java.util.Collections$UnmodifiableRandomAccessList",
  "java.util.Collections$SynchronizedList",
  "java.util.Collections$SynchronizedRandomAccessList",
  "java.util.Collections$CheckedList",
  "java.util.Collections$EmptyList",
  "java.util.AbstractList$SubList",
  // java.util - Sets
  "java.util.HashSet",
  "java.util.LinkedHashSet",
  "java.util.TreeSet",
  "java.util.Collections$SingletonSet",
  "java.util.Collections$UnmodifiableSet",
  "java.util.Collections$UnmodifiableSortedSet",
  "java.util.Collections$SynchronizedSet",
  "java.util.Collections$CheckedSet",
  "java.util.Collections$EmptySet",
  "java.util.EnumSet",
  "java.util.RegularEnumSet",
  "java.util.JumboEnumSet",
  // java.util - Queues
  "java.util.ArrayDeque",
  "java.util.PriorityQueue",
  // java.util.concurrent
  "java.util.concurrent.CopyOnWriteArrayList",
  "java.util.concurrent.CopyOnWriteArraySet",
  "java.util.concurrent.ConcurrentLinkedQueue",
  "java.util.concurrent.ConcurrentLinkedDeque",
  "java.util.concurrent.LinkedBlockingQueue",
  "java.util.concurrent.ArrayBlockingQueue",
  "java.util.concurrent.PriorityBlockingQueue",
  "java.util.concurrent.LinkedBlockingDeque",
  "java.util.concurrent.ConcurrentSkipListSet",
  // Android
  "android.util.ArraySet",
  "android.database.MatrixCursor",
  "android.database.MergeCursor",
  "androidx.collection.ArraySet",
  "androidx.collection.SimpleArrayMap",
];

const mapClasses: string[] = [
  // java.util
  "java.util.HashMap",
  "java.util.LinkedHashMap",
  "java.util.TreeMap",
  "java.util.Hashtable",
  "java.util.IdentityHashMap",
  "java.util.WeakHashMap",
  "java.util.EnumMap",
  "java.util.Collections$SingletonMap",
  "java.util.Collections$UnmodifiableMap",
  "java.util.Collections$UnmodifiableSortedMap",
  "java.util.Collections$SynchronizedMap",
  "java.util.Collections$CheckedMap",
  "java.util.Collections$EmptyMap",
  // java.util.concurrent
  "java.util.concurrent.ConcurrentHashMap",
  "java.util.concurrent.ConcurrentSkipListMap",
  // Android
  "android.util.ArrayMap",
  "android.util.SparseArray",
  "android.util.SparseBooleanArray",
  "android.util.SparseIntArray",
  "android.util.SparseLongArray",
  "android.util.LongSparseArray",
  "android.util.LruCache",
  "androidx.collection.ArrayMap",
  "androidx.collection.LruCache",
  "androidx.collection.LongSparseArray",
  "androidx.collection.SparseArrayCompat",
];

const javaClassDecoderRegistry: Record<string, DecoderConstructor> = {
  ...Object.fromEntries(iterableClasses.map((c) => [c, IterableDecoder])),
  ...Object.fromEntries(mapClasses.map((c) => [c, MapDecoder])),

  // custom decoders
  "android.security.keystore.KeyGenParameterSpec": KeyGenParameterSpecDecoder,
  "android.content.IntentFlagDecoder": IntentFlagDecoder,
};

export class JavaClassDecoder extends Decoder<Java.Wrapper> {
  implementationDecoder: Decoder<Java.Wrapper> | undefined;

  decode(value: Java.Wrapper): DecodedValue {
    if (!this.implementationDecoder) {
      // Try to find a decoder in the registry with fall back to JavaFallbackDecoder
      const implementationType = value.$className ?? this.decodable.type;
      const DecoderClass = javaClassDecoderRegistry[implementationType];
      this.implementationDecoder = DecoderClass
        ? new DecoderClass({
            type: implementationType,
            name: this.decodable.name,
            settings: this.decodable.settings,
          })
        : new JavaFallbackDecoder(this.decodable);
    }

    return {
      type: this.decodable.type,
      name: this.decodable.name,
      value: this.implementationDecoder.decode(value),
    };
  }
}

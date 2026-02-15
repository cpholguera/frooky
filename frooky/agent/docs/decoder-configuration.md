# Decoder Configuration

When ever the frooky agent hooks a function on method, it tries to decode the arguments passed to it as well as the value returned to the caller.

Depending on the type this can be fairly simle. Primitives, such as Integers, Floats or Shorts can be always be decoded by the frooky agent. However, some values required more complex decoders.

They are required, if the either the time of decoding varies, or if more context information is required. The following two chapters explain these cases.

## Time of Decoding

By default, arguments are decoded when the function or method is called. Larger datastrucutres, such as arrays are often passed by reference with the intention to manipulate them within the function or method.

> [!NOTE]
> **Example: Java method `doFinal` from `javax.crypto.Cipher`**
>
> ```java
> public final int doFinal(byte[] output, 
>                          int outputOffset)
>  ```
>
> This method de- or encrypts the data stored in the current object and writes the output into the byte array `output`.  If we want to access the de- or encrypted `output`, we must decode the value after the method completes.

## Parameterized Decoder

In native functions, primitive arrays are passed by reference. However, in some cases, , the length must be explicitly stated.

Method and functions therefore declare parameters which are used to determine the length of another parameter.

> [!NOTE]
> **Example: Native OpenSSL function with array passed by reference:**
>
> ```c
> int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, 
>                       unsigned char *out,
>                       int *outl, 
>                       const unsigned char *in, 
>                       int inl);
> ```
>
> This function encrypts `inl` bytes from the buffer `in` and writes the encrypted version to `out`. Depending on the type of encryption algorithm used, it is unclear how many bytes will be written at the time the function is called. The actual number of bytes written, is placed in  `outl`.

If we want to decode `out` we mus first do that after the function completes (see [Time of Decoding](#time-of-decoding)) and pass the number of bytes to decode (`outl`) to the decoder.

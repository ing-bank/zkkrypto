# ZKKrypto

This repository contains cryptographic primitives mostly used in a ZKP context. The goal is to gather a collection of ZKP-related crypto algorithms written in Kotlin in a single place to simplify research and development.

Currently, following algorithms are implemented:

- Pedersen hash
- Edwards curve arithmetics
- Curves: Jubjub, BabyJubjub, AltBabyJubjub

### Getting started

To use zkkrypto as Gradle dependency add Bintray Jcenter to the 'repositories' list.

```
repositories {
    ...
    jcenter()
    ...
}
```
Then you can use zkkrypto package in your dependencies:
```
dependencies {
    ...
    implementation "com.ing.dlt:zkkrypto:{VERSION}"
    ...
}
```
Done! Now import chosen primitives and knock yourself out.

### Work in progress

We are going to support this repo and to add new algorithms to it. So if you are interested in particular primitives - let us know. Push requests are highly appreciated as well.


### Disclamer

Code is released under Apache license so feel free to use it wherever you want. 

Although please keep in mind that it comes with absolutely no warranty so before using it in production - please make sure you know what you are doing. 

### Contacts

For any questions either create an Issue or just poke somebody from our team directly. E.g.:

[Alexey Koren](https://www.linkedin.com/in/alexeykoren/ "LinkedIn")

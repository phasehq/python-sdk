# Python SDK for Phase

SDK to integrate Phase in server-side applications running Python

## Install

`pip install phase-sdk`

## Import

```python
from phase import Phase;
```

## Initialize

Initialize the SDK with your `APP_ID` and `APP_SECRET`:

```python
phase = Phase(APP_ID, APP_SECRET)
```

## Usage

### Encrypt

```python
ciphertext = phase.encrypt("hello world");
```

### Decrypt

```python
plaintext = phase.decrypt(ciphertext);
```

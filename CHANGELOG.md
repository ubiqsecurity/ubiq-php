# Changelog

## 2.1.0 - 05/22/2026
* Added typed encrypt/decrypt for integer, date, and datetime structured datasets (`encryptInteger` / `decryptInteger` / `encryptDate` / `decryptDate` / `encryptDateTime` / `decryptDateTime`) for parity with ubiq-java and ubiq-dotnet
* Added typed encryptForSearch variants (`encryptIntegerForSearch` / `encryptDateForSearch` / `encryptDateTimeForSearch`) for searching across encrypted typed columns under historical key rotations — parity with ubiq-java `encryptIntForSearch` / `encryptLongForSearch` / `encryptDateForSearch` / `encryptDateTimeForSearch` and ubiq-dotnet `EncryptForSearchAsync` overloads
* `\Ubiq\encryptForSearch` now rejects typed datasets with a message pointing to the matching typed search helper, matching the typed-rejection behavior of `encrypt` / `decrypt`
* Added `data_type` and `data_type_config` typed accessors on `Dataset` plus a new `DataTypeConfig` class mirroring `com.ubiqsecurity.DataTypeConfig` (Java) and `UbiqSecurity.Internals.WebService.Models.DataTypeConfig` (.NET)
* Added input-encoding / input-padding pipeline operations (`Ubiq\Pipeline\EncodeInputOperation`, `DecodeInputOperation`, `PadInputOperation`) so datasets with `input_encoding = base64|base32` or `input_pad_character` round-trip through `encrypt` / `decrypt` automatically
* Added `\Ubiq\loadCache` for single-network-call prefetch of dataset configs + encryption keys across many datasets, with empty / null input meaning "fetch every dataset the API key can access" — matches the ubiq-go `loadCache` flow (ubiq-java has the equivalent internal helper `getFpeDefKeys`)
* Fixed `KeyManager::getAllEncryptionKeys` silently dropping every dataset after the first in a multi-dataset response (the cache only contained the first dataset's keys)
* `\Ubiq\encrypt` and `\Ubiq\decrypt` now reject non-string `data_type` datasets with a message pointing to the correct typed entry point
* Replaced the in-tree `tests/DATA/*.json` fixtures (~470 MB) with the shared `ubiq-test-data` submodule at `tests/ubiq-test-data`, matching ubiq-java / ubiq-dotnet — run `git submodule update --init` after checkout

## 2.0.1 - 12/16/2024
* Fix composer autoloading
* Update composer install instructions

## 2.0.0 - 11/28/2024
* Added support for structured datasets
* Added encryptForSearch method
* Added user defined metadata to events
* Configurable error handling for event reporting
* Time granularity for event reporting
* Add support for cache TTL
* Update config structure

## 0.1.0 - 6/27/2023
* Added key caching for unstructured data
* Added cache manager singleton for key and event log (and eventually dataset) caching
* Added event reporting
* Removed piecewise (replaced with caching)
* Removed inline /v0 event reporting
* Refactors for cleanliness and linting
* Updated tests

## 0.0.2 - 1/18/2022
* Fixed API failures when local PHP timezone is not set to UTC

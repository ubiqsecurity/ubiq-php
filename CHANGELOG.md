# Changelog

## 2.0.0 - 6/27/2023
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

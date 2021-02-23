QUIET	:= @

test: cs
	$(QUIET)./vendor/phpunit/phpunit/phpunit \
	  --configuration phpunit.xml \
	  --coverage-text --colors=never \
	  --testdox tests/

cs:
	$(QUIET)-./vendor/squizlabs/php_codesniffer/bin/phpcs \
	  src/ tests/ examples/ \
	  --report=full \
	  --report-\\Micheh\\PhpCodeSniffer\\Report\\Gitlab=phpcs.json

setup:
	$(QUIET)composer install

docker:
	$(QUIET)sudo docker build -t ubiq-php-dev .

docker-run: docker
	$(QUIET)sudo docker run --rm -it -v$$(pwd):$$(pwd) ubiq-php-dev

.PHONY: setup test cs docker docker-run

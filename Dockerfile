FROM debian:stable

RUN apt -y update &&            \
    apt -y install              \
        composer                \
        make                    \
        php-curl                \
	php-xdebug		\
        php-xml
RUN apt -y remove --purge	\
	git

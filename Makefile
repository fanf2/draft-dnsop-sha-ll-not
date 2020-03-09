MMARK=${GOPATH}/bin/mmark

DRAFT=draft-fanf-dnsop-sha-ll-not-00

OUT= ${DRAFT}.html ${DRAFT}.xml ${DRAFT}.txt

.PHONY: all clean commit stamp

all: ${OUT}

${DRAFT}.html: ${DRAFT}.2.xml
	xml2rfc --html -o ${DRAFT}.html ${DRAFT}.2.xml

${DRAFT}.xml: draft.md
	${MMARK} draft.md >${DRAFT}.xml

${DRAFT}.2.xml: draft.md
	${MMARK} -2 draft.md >${DRAFT}.2.xml

${DRAFT}.txt: ${DRAFT}.2.xml
	xml2rfc --raw -o ${DRAFT}.txt ${DRAFT}.2.xml

commit: stamp ${OUT}
	git add draft.md ${OUT}
	git commit -m 'Update rendered versions'

stamp:
	./stamp.sh ${DRAFT} draft.md

clean:
	rm -f ${OUT}

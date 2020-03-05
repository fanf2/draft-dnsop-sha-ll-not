MMARK=${GOPATH}/bin/mmark

DRAFT=draft-fanf-dnsop-sha-ll-not

OUT= ${DRAFT}.html ${DRAFT}.xml ${DRAFT}.txt

.PHONY: all clean commit stamp

all: ${OUT}

${DRAFT}.html: ${DRAFT}.xml
	xml2rfc --html -o ${DRAFT}.html ${DRAFT}.xml

${DRAFT}.xml: draft.md
	${MMARK} -2 draft.md >${DRAFT}.xml

${DRAFT}.txt: ${DRAFT}.xml
	xml2rfc --raw -o ${DRAFT}.txt ${DRAFT}.xml

commit: stamp ${OUT}
	git add ${OUT}
	git commit -m 'Update rendered versions'

stamp:
	./stamp.sh draft.md

clean:
	rm -f ${OUT}

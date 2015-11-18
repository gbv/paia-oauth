index.html: README.md
	pandoc -t html5 -s --template template.html --toc $< | \
	   sed 's/<table>/<table class="table table-bordered">/' > $@

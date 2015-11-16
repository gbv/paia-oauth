index.html: README.md
	pandoc -o $@ -s --template template.html --toc $< 

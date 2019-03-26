NAME=cryptocoding

$(NAME).pdf: *.tex 
	pdflatex --shell-escape -synctex=1 -interaction=nonstopmode $(NAME)
	pdflatex --shell-escape -synctex=1 -interaction=nonstopmode $(NAME)

update: 
	pdflatex --shell-escape $(NAME)

clean:
	latexmk -c
	rm -f *.aux *.loc *.toc	*.log *.pytxcode *.out *.pyg *.synctex.gz
	rm -fr _minted-* 

compile: 
	pdflatex --shell-escape -synctex=1 -interaction=nonstopmode $(NAME)
	pdflatex --shell-escape -synctex=1 -interaction=nonstopmode $(NAME)
	rm -f *.aux *.loc *.toc	*.log *.pytxcode *.out *.pyg *.bbl *.blg *.synctex.gz
	rm -fr _minted-* 


package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

func TestServiceAuthenticationWrapsRequestSizeLimit(t *testing.T) {
	file := parseHTTPAPISource(t, "http.go")
	function := findFunction(t, file, "newHandler")

	var returnExpression ast.Expr
	ast.Inspect(function.Body, func(node ast.Node) bool {
		statement, ok := node.(*ast.ReturnStmt)
		if !ok || len(statement.Results) != 1 {
			return true
		}
		returnExpression = statement.Results[0]
		return false
	})

	outerCall, ok := returnExpression.(*ast.CallExpr)
	if !ok {
		t.Fatalf("newHandler return = %T, want service authenticator wrap call", returnExpression)
	}
	selector, ok := outerCall.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "wrap" {
		t.Fatalf("newHandler return function = %#v, want .wrap", outerCall.Fun)
	}
	authenticator, ok := selector.X.(*ast.CallExpr)
	if !ok || !isCallTo(authenticator, "newServiceAuthenticator") {
		t.Fatalf("wrap receiver = %#v, want newServiceAuthenticator(...)", selector.X)
	}
	if len(outerCall.Args) != 1 || !isCallToExpression(outerCall.Args[0], "requestSizeLimit") {
		t.Fatalf("wrap arguments = %#v, want requestSizeLimit(mux)", outerCall.Args)
	}
}

func TestServiceAuthenticationUsesConstantTimeComparisonForBothTokens(t *testing.T) {
	file := parseHTTPAPISource(t, "auth.go")
	function := findFunction(t, file, "authenticate")

	constantTimeComparisons := 0
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "ConstantTimeCompare" {
			return true
		}
		packageName, ok := selector.X.(*ast.Ident)
		if ok && packageName.Name == "subtle" {
			constantTimeComparisons++
		}
		return true
	})
	if constantTimeComparisons != 2 {
		t.Fatalf("authenticate() ConstantTimeCompare calls = %d, want 2 for current and previous tokens", constantTimeComparisons)
	}
}

func parseHTTPAPISource(t *testing.T, name string) *ast.File {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("find authentication invariant test file")
	}
	path := filepath.Join(filepath.Dir(testFile), name)
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return file
}

func findFunction(t *testing.T, file *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == name {
			return function
		}
	}
	t.Fatalf("function %q is missing", name)
	return nil
}

func isCallTo(call *ast.CallExpr, name string) bool {
	identifier, ok := call.Fun.(*ast.Ident)
	return ok && identifier.Name == name
}

func isCallToExpression(expression ast.Expr, name string) bool {
	call, ok := expression.(*ast.CallExpr)
	return ok && isCallTo(call, name)
}

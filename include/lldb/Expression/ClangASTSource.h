/*
 *  ClangASTSource.h
 *  lldb
 *
 *  Created by John McCall on 6/1/10.
 *  Copyright 2010 Apple. All rights reserved.
 *
 */
#ifndef liblldb_ClangASTSource_h_
#define liblldb_ClangASTSource_h_

#include "clang/Sema/ExternalSemaSource.h"

namespace lldb_private {
    
class ClangExpressionDeclMap;

class ClangASTSource : public clang::ExternalSemaSource {
	clang::ASTContext &Context;
	ClangExpressionDeclMap &DeclMap;
public:
    friend struct NameSearchContext;
    
	ClangASTSource(clang::ASTContext &context,
                   ClangExpressionDeclMap &declMap) : 
        Context(context),
        DeclMap(declMap) {}
	~ClangASTSource();
	
    clang::Decl *GetExternalDecl(uint32_t);
    clang::Stmt *GetExternalDeclStmt(uint64_t);
	
    clang::Selector GetExternalSelector(uint32_t);
	uint32_t GetNumExternalSelectors();
	
    clang::DeclContext::lookup_result FindExternalVisibleDeclsByName(const clang::DeclContext *DC,
                                                                     clang::DeclarationName Name);
	
	bool FindExternalLexicalDecls(const clang::DeclContext *DC,
                                  llvm::SmallVectorImpl<clang::Decl*> &Decls);
    
    void StartTranslationUnit(clang::ASTConsumer *Consumer);
};
    
// API for ClangExpressionDeclMap
struct NameSearchContext {
    ClangASTSource &ASTSource;
    llvm::SmallVectorImpl<clang::NamedDecl*> &Decls;
    clang::DeclarationName &Name;
    const clang::DeclContext *DC;
    
    NameSearchContext (ClangASTSource &astSource,
                       llvm::SmallVectorImpl<clang::NamedDecl*> &decls,
                       clang::DeclarationName &name,
                       const clang::DeclContext *dc) :
        ASTSource(astSource),
        Decls(decls),
        Name(name),
        DC(dc) {}
    
    clang::ASTContext *GetASTContext();
    clang::NamedDecl *AddVarDecl(void *type);
    clang::NamedDecl *AddFunDecl(void *type);
};

}

#endif
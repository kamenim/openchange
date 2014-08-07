#!/usr/bin/python

TEST_USERNAME = 'm1'
CONTEXT_URL_INBOX = 'sogo://m1:m1@mail/folderINBOX/'

from openchange import mapistore

def test_single_context(mstore, context_url, username):
    global TEST_USERNAME
    mctx = mstore.add_context(context_url, username)
    folder = mctx.open()
    folder.fetch_freebusy_properties()
    for table_type in range(1, 7):
        folder.get_child_count(table_type)
    del mctx


def test_all_contexts(mstore):
    global TEST_USERNAME
    all_contexts = mstore.list_contexts_for_user(TEST_USERNAME)
    # print all_contexts
    for ctx in all_contexts:
        test_single_context(mstore, ctx['url'], TEST_USERNAME)


mstore = mapistore.MAPIStoreDirect()
# print mstore.list_contexts_for_user('m1')
# mctx = mstore.add_context('sogo://m1:m1@mail/folderSpam', 'm1')
# mctx = mstore.add_context('sogo://m1:m1@mail/folderJunk_SP_E-mail', 'm1')
# mctx = mstore.add_context('sogo://m1:m1@mail/folderINBOX/', TEST_USERNAME)
# mstore.del_context(mctx)
# test_all_contexts(mstore)

test_single_context(mstore, CONTEXT_URL_INBOX, TEST_USERNAME)

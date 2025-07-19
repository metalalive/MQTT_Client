#include "mqtt_include.h"

// Define a simple struct to embed tlsListItem_t for testing
typedef struct {
    tlsListItem_t list_item;
    int           value;
} MyListItem;

// Helper function to free MyListItem objects
static void freeMyList(tlsListItem_t **list) {
    tlsListItem_t *current = *list;
    while (current != NULL) {
        tlsListItem_t *next = current->next;
        XMEMFREE(current);
        current = next;
    }
    *list = NULL;
}

// ------------------------------------------------------------
TEST_GROUP(tlsUtilListFunctions);

static tlsListItem_t *test_list_head = NULL;

TEST_SETUP(tlsUtilListFunctions) {
    test_list_head = NULL; // Ensure list is empty before each test
}

TEST_TEAR_DOWN(tlsUtilListFunctions) {
    freeMyList(&test_list_head); // Clean up list after each test
}

TEST_GROUP_RUNNER(tlsUtilListFunctions) {
    RUN_TEST_CASE(tlsUtilListFunctions, test_addItemToList_front);
    RUN_TEST_CASE(tlsUtilListFunctions, test_addItemToList_back);
    RUN_TEST_CASE(tlsUtilListFunctions, test_addItemToList_null_args);
    RUN_TEST_CASE(tlsUtilListFunctions, test_getListItemSz);
    RUN_TEST_CASE(tlsUtilListFunctions, test_getFinalItemFromList);
    RUN_TEST_CASE(tlsUtilListFunctions, test_removeItemFromList_head);
    RUN_TEST_CASE(tlsUtilListFunctions, test_removeItemFromList_middle);
    RUN_TEST_CASE(tlsUtilListFunctions, test_removeItemFromList_tail);
    RUN_TEST_CASE(tlsUtilListFunctions, test_removeItemFromList_nonExistent);
    RUN_TEST_CASE(tlsUtilListFunctions, test_removeItemFromList_null_args);
}

TEST(tlsUtilListFunctions, test_addItemToList_front) {
    tlsRespStatus status;
    MyListItem   *item1, *item2, *item3;

    // Add first item to front (list is empty)
    item1 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    TEST_ASSERT_NOT_NULL(item1);
    item1->value = 10;
    status = tlsAddItemToList(&test_list_head, &item1->list_item, 1);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_PTR(&item1->list_item, test_list_head);
    TEST_ASSERT_EQUAL_INT(1, tlsGetListItemSz(test_list_head));

    // Add second item to front
    item2 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    TEST_ASSERT_NOT_NULL(item2);
    item2->value = 20;
    status = tlsAddItemToList(&test_list_head, &item2->list_item, 1);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_PTR(&item2->list_item, test_list_head);
    TEST_ASSERT_EQUAL_PTR(&item1->list_item, test_list_head->next);
    TEST_ASSERT_EQUAL_INT(2, tlsGetListItemSz(test_list_head));

    // Add third item to front
    item3 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    TEST_ASSERT_NOT_NULL(item3);
    item3->value = 30;
    status = tlsAddItemToList(&test_list_head, &item3->list_item, 1);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_PTR(&item3->list_item, test_list_head);
    TEST_ASSERT_EQUAL_PTR(&item2->list_item, test_list_head->next);
    TEST_ASSERT_EQUAL_PTR(&item1->list_item, test_list_head->next->next);
    TEST_ASSERT_EQUAL_INT(3, tlsGetListItemSz(test_list_head));

    // Verify order and values
    TEST_ASSERT_EQUAL_INT(30, ((MyListItem *)test_list_head)->value);
    TEST_ASSERT_EQUAL_INT(20, ((MyListItem *)test_list_head->next)->value);
    TEST_ASSERT_EQUAL_INT(10, ((MyListItem *)test_list_head->next->next)->value);
}

TEST(tlsUtilListFunctions, test_addItemToList_back) {
    tlsRespStatus status;
    MyListItem   *item1, *item2, *item3;

    // Add first item to back (list is empty)
    item1 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    TEST_ASSERT_NOT_NULL(item1);
    item1->value = 10;
    status = tlsAddItemToList(&test_list_head, &item1->list_item, 0);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_PTR(&item1->list_item, test_list_head);
    TEST_ASSERT_EQUAL_INT(1, tlsGetListItemSz(test_list_head));

    // Add second item to back
    item2 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    TEST_ASSERT_NOT_NULL(item2);
    item2->value = 20;
    status = tlsAddItemToList(&test_list_head, &item2->list_item, 0);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_PTR(&item1->list_item, test_list_head);
    TEST_ASSERT_EQUAL_PTR(&item2->list_item, test_list_head->next);
    TEST_ASSERT_EQUAL_INT(2, tlsGetListItemSz(test_list_head));

    // Add third item to back
    item3 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    TEST_ASSERT_NOT_NULL(item3);
    item3->value = 30;
    status = tlsAddItemToList(&test_list_head, &item3->list_item, 0);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_PTR(&item1->list_item, test_list_head);
    TEST_ASSERT_EQUAL_PTR(&item2->list_item, test_list_head->next);
    TEST_ASSERT_EQUAL_PTR(&item3->list_item, test_list_head->next->next);
    TEST_ASSERT_EQUAL_INT(3, tlsGetListItemSz(test_list_head));

    // Verify order and values
    TEST_ASSERT_EQUAL_INT(10, ((MyListItem *)test_list_head)->value);
    TEST_ASSERT_EQUAL_INT(20, ((MyListItem *)test_list_head->next)->value);
    TEST_ASSERT_EQUAL_INT(30, ((MyListItem *)test_list_head->next->next)->value);
}

TEST(tlsUtilListFunctions, test_addItemToList_null_args) {
    tlsRespStatus status;
    MyListItem   *item1 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    TEST_ASSERT_NOT_NULL(item1);
    item1->value = 10;

    // Test with NULL list pointer
    status = tlsAddItemToList(NULL, &item1->list_item, 0);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERRARGS, status);

    // Test with NULL item pointer
    status = tlsAddItemToList(&test_list_head, NULL, 0);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERRARGS, status);

    // Clean up manually as test_tear_down won't free item1 if it wasn't added to the list
    XMEMFREE(item1);
}

TEST(tlsUtilListFunctions, test_getListItemSz) {
    tlsRespStatus status;
    MyListItem   *item1, *item2, *item3;

    TEST_ASSERT_EQUAL_INT(0, tlsGetListItemSz(test_list_head));

    item1 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    item1->value = 10;
    status = tlsAddItemToList(&test_list_head, &item1->list_item, 0);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_INT(1, tlsGetListItemSz(test_list_head));

    item2 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    item2->value = 20;
    status = tlsAddItemToList(&test_list_head, &item2->list_item, 0);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_INT(2, tlsGetListItemSz(test_list_head));

    item3 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    item3->value = 30;
    status = tlsAddItemToList(&test_list_head, &item3->list_item, 0);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_INT(3, tlsGetListItemSz(test_list_head));

    // Test with NULL list
    TEST_ASSERT_EQUAL_INT(0, tlsGetListItemSz(NULL));
}

TEST(tlsUtilListFunctions, test_getFinalItemFromList) {
    tlsRespStatus status;
    MyListItem   *item1, *item2, *item3;

    // Empty list
    TEST_ASSERT_EQUAL_PTR(NULL, tlsGetFinalItemFromList(test_list_head));

    // One item
    item1 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    item1->value = 10;
    status = tlsAddItemToList(&test_list_head, &item1->list_item, 0);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_PTR(&item1->list_item, tlsGetFinalItemFromList(test_list_head));

    // Multiple items
    item2 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    item2->value = 20;
    status = tlsAddItemToList(&test_list_head, &item2->list_item, 0);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    item3 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    item3->value = 30;
    status = tlsAddItemToList(&test_list_head, &item3->list_item, 0);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);

    TEST_ASSERT_EQUAL_PTR(&item3->list_item, tlsGetFinalItemFromList(test_list_head));

    // Test with NULL list
    TEST_ASSERT_EQUAL_PTR(NULL, tlsGetFinalItemFromList(NULL));
}

TEST(tlsUtilListFunctions, test_removeItemFromList_head) {
    tlsRespStatus status;
    MyListItem   *item1, *item2, *item3;

    item1 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    item1->value = 10;
    item2 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    item2->value = 20;
    item3 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    item3->value = 30;

    tlsAddItemToList(&test_list_head, &item1->list_item, 0);
    tlsAddItemToList(&test_list_head, &item2->list_item, 0);
    tlsAddItemToList(&test_list_head, &item3->list_item, 0);
    TEST_ASSERT_EQUAL_INT(3, tlsGetListItemSz(test_list_head));

    // Remove head item (item1)
    status = tlsRemoveItemFromList(&test_list_head, &item1->list_item);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_INT(2, tlsGetListItemSz(test_list_head));
    TEST_ASSERT_EQUAL_PTR(&item2->list_item, test_list_head); // New head should be item2
    TEST_ASSERT_EQUAL_PTR(&item3->list_item, test_list_head->next);
    XMEMFREE(item1); // Manually free the removed item

    // Remove new head item (item2)
    status = tlsRemoveItemFromList(&test_list_head, &item2->list_item);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_INT(1, tlsGetListItemSz(test_list_head));
    TEST_ASSERT_EQUAL_PTR(&item3->list_item, test_list_head); // New head should be item3
    TEST_ASSERT_EQUAL_PTR(NULL, test_list_head->next);
    XMEMFREE(item2); // Manually free the removed item

    // Remove last item (item3)
    status = tlsRemoveItemFromList(&test_list_head, &item3->list_item);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_INT(0, tlsGetListItemSz(test_list_head));
    TEST_ASSERT_EQUAL_PTR(NULL, test_list_head); // List should be empty
    XMEMFREE(item3);                             // Manually free the removed item
}

TEST(tlsUtilListFunctions, test_removeItemFromList_middle) {
    tlsRespStatus status;
    MyListItem   *item1, *item2, *item3;

    item1 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    item1->value = 10;
    item2 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    item2->value = 20;
    item3 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    item3->value = 30;

    tlsAddItemToList(&test_list_head, &item1->list_item, 0);
    tlsAddItemToList(&test_list_head, &item2->list_item, 0);
    tlsAddItemToList(&test_list_head, &item3->list_item, 0);
    TEST_ASSERT_EQUAL_INT(3, tlsGetListItemSz(test_list_head));

    // Remove middle item (item2)
    status = tlsRemoveItemFromList(&test_list_head, &item2->list_item);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_INT(2, tlsGetListItemSz(test_list_head));
    TEST_ASSERT_EQUAL_PTR(&item1->list_item, test_list_head);
    TEST_ASSERT_EQUAL_PTR(
        &item3->list_item, test_list_head->next
    );               // item1 should now point to item3
    XMEMFREE(item2); // Manually free the removed item
}

TEST(tlsUtilListFunctions, test_removeItemFromList_tail) {
    tlsRespStatus status;
    MyListItem   *item1, *item2, *item3;

    item1 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    item1->value = 10;
    item2 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    item2->value = 20;
    item3 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    item3->value = 30;

    tlsAddItemToList(&test_list_head, &item1->list_item, 0);
    tlsAddItemToList(&test_list_head, &item2->list_item, 0);
    tlsAddItemToList(&test_list_head, &item3->list_item, 0);
    TEST_ASSERT_EQUAL_INT(3, tlsGetListItemSz(test_list_head));

    // Remove tail item (item3)
    status = tlsRemoveItemFromList(&test_list_head, &item3->list_item);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status);
    TEST_ASSERT_EQUAL_INT(2, tlsGetListItemSz(test_list_head));
    TEST_ASSERT_EQUAL_PTR(&item1->list_item, test_list_head);
    TEST_ASSERT_EQUAL_PTR(&item2->list_item, test_list_head->next);
    TEST_ASSERT_EQUAL_PTR(NULL, test_list_head->next->next); // item2 should now be the tail
    XMEMFREE(item3);                                         // Manually free the removed item
}

TEST(tlsUtilListFunctions, test_removeItemFromList_nonExistent) {
    tlsRespStatus status;
    MyListItem   *item1, *item2, *non_existent_item;

    item1 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    item1->value = 10;
    item2 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    item2->value = 20;
    non_existent_item = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    non_existent_item->value = 99;

    tlsAddItemToList(&test_list_head, &item1->list_item, 0);
    tlsAddItemToList(&test_list_head, &item2->list_item, 0);
    TEST_ASSERT_EQUAL_INT(2, tlsGetListItemSz(test_list_head));

    // Attempt to remove a non-existent item
    status = tlsRemoveItemFromList(&test_list_head, &non_existent_item->list_item);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_OK, status); // Function returns OK even if not found
    TEST_ASSERT_EQUAL_INT(2, tlsGetListItemSz(test_list_head)); // List size should be unchanged
    TEST_ASSERT_EQUAL_PTR(&item1->list_item, test_list_head);
    TEST_ASSERT_EQUAL_PTR(&item2->list_item, test_list_head->next);

    XMEMFREE(non_existent_item); // Manually free the non-existent item
}

TEST(tlsUtilListFunctions, test_removeItemFromList_null_args) {
    tlsRespStatus status;
    MyListItem   *item1 = (MyListItem *)XCALLOC(1, sizeof(MyListItem));
    TEST_ASSERT_NOT_NULL(item1);
    item1->value = 10;
    tlsAddItemToList(&test_list_head, &item1->list_item, 0);

    // Test with NULL list pointer
    status = tlsRemoveItemFromList(NULL, &item1->list_item);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERRARGS, status);

    // Test with NULL item pointer
    status = tlsRemoveItemFromList(&test_list_head, NULL);
    TEST_ASSERT_EQUAL_INT(TLS_RESP_ERRARGS, status);
}

static void RunAllTestGroups(void) {
    RUN_TEST_GROUP(tlsUtilListFunctions);
} // end of RunAllTestGroups

int main(int argc, const char *argv[]) {
    return UnityMain(argc, argv, RunAllTestGroups);
} // end of main

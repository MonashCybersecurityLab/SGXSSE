#include "AVLTree.h"

AVLTree::AVLTree(const unsigned char *key, int _numBucketLeaf, int data_structure)
{
    oram = new Oram(key, _numBucketLeaf, data_structure);
}

AVLTree::~AVLTree(){
    delete oram;
}

int AVLTree::height(Bid key, unsigned int& leaf) {
    if (key == empty_key)
        return 0;
    Node* node = oram->ReadNode(key, leaf, leaf);
    return node->height;
}

int AVLTree::max(int a, int b) {
    return (a > b) ? a : b;
}

Node* AVLTree::newNode(Bid key, unsigned int value) {
    Node* node = new Node();
    
    node->key = key;
    node->value = value;

    node->leftID = empty_key;
    node->rightID = empty_key;
    node->pos = oram->RandomPath();
    node->height = 1; // new node is initially added at leaf
    return node;
}

Node* AVLTree::rightRotate(Node* y) {
    Node* x = oram->ReadNode(y->leftID);
    Node* T2;
    if (x->rightID == empty_key) {
        T2 = newNode(empty_key, 0);
    } else {
        T2 = oram->ReadNode(x->rightID);
    }

    //printf("rightRotate: T2, key (%s), pos (%d)", (char*)T2->key.key, T2->pos);

    // Perform rotation
    x->rightID = y->key;
    x->rightPos = y->pos;
    y->leftID = T2->key;
    y->leftPos = T2->pos;

    // Update heights
    y->height = max(height(y->leftID, y->leftPos), height(y->rightID, y->rightPos)) + 1;
    oram->WriteNode(y->key, y);
    x->height = max(height(x->leftID, x->leftPos), height(x->rightID, x->rightPos)) + 1;
    oram->WriteNode(x->key, x);
    // Return new root

    //printf("Node with key(%s) updates its height with: %d", x->key.key, x->height);
    //printf("Node with key(%s) updates its height with: %d", y->key.key, y->height);

    return x;
}

Node* AVLTree::leftRotate(Node* x) {
    Node* y = oram->ReadNode(x->rightID);
    Node* T2;
    if (y->leftID == empty_key) {
        T2 = newNode(empty_key, 0);
    } else {
        T2 = oram->ReadNode(y->leftID);
    }

    //printf("leftRotate: T2, key (%s), pos (%d)", (char*)T2->key.key, T2->pos);

    // Perform rotation
    y->leftID = x->key;
    y->leftPos = x->pos;
    x->rightID = T2->key;
    x->rightPos = T2->pos;

    // Update heights
    x->height = max(height(x->leftID, x->leftPos), height(x->rightID, x->rightPos)) + 1;
    oram->WriteNode(x->key, x);
    y->height = max(height(y->leftID, y->leftPos), height(y->rightID, y->rightPos)) + 1;
    oram->WriteNode(y->key, y);
    // Return new root

    //printf("Node with key(%s) updates its height with: %d", x->key.key, x->height);
    //printf("Node with key(%s) updates its height with: %d", y->key.key, y->height);

    return y;
}

int AVLTree::getBalance(Node* N) {
    if (N == NULL)
        return 0;
    return height(N->leftID, N->leftPos) - height(N->rightID, N->rightPos);
}


Bid AVLTree::insert(Bid rootKey, unsigned int& pos, Bid key, unsigned int value) {
    /* 1. Perform the normal BST rotation */
    if (rootKey == empty_key) {
        Node* nnode = newNode(key, value);
        //printf("insert: create node (key:%s pos %d, value: %d)",nnode->key.key,nnode->pos, nnode->value);
        pos = oram->WriteNode(key, nnode);
        return nnode->key;
    }
    Node* node = oram->ReadNode(rootKey, pos, pos);
    //printf("Node with key(%s) , (pos: %d), (value: %d) is readed.", node->key.key,node->pos, node->value);

    if (key < node->key) {
        //printf("insert: checking left");
        node->leftID = insert(node->leftID, node->leftPos, key, value);
    } else if (key > node->key) {
        //printf("insert: checking right");
        node->rightID = insert(node->rightID, node->rightPos, key, value);
    } else {
        node->value=value;
        oram->WriteNode(rootKey, node);
        //printf("Node with key(%s) is existed and updated with new value: %d", node->key.key, value);
        return node->key;
    }

    /* 2. Update height of this ancestor node */
    //printf("Start updating the height of node with key (%s)", node->key.key);
   
    node->height = max(height(node->leftID, node->leftPos), height(node->rightID, node->rightPos)) + 1;
    
    //printf("Node with key(%s) updates its height with: %d", node->key.key, node->height);

    /* 3. Get the balance factor of this ancestor node to check whether
       this node became unbalanced */
    int balance = getBalance(node);

    //printf("Node with key(%s)'s current balance: %d", node->key.key, balance);

    // If this node becomes unbalanced, then there are 4 cases

    // Left Left Case
    if (balance > 1 && key < oram->ReadNode(node->leftID)->key) {
        //printf("AVLTree->insert: Left Left Case");
        Node* res = rightRotate(node);
        pos = res->pos;
        return res->key;
    }

    // Right Right Case
    if (balance < -1 && key > oram->ReadNode(node->rightID)->key) {
        //printf("AVLTree->insert: Right Right Case");
        Node* res = leftRotate(node);
        pos = res->pos;
        return res->key;
    }

    // Left Right Case
    if (balance > 1 && key > oram->ReadNode(node->leftID)->key) {
        //printf("AVLTree->insert: Left Right Case");
        Node* res = leftRotate(oram->ReadNode(node->leftID));
        node->leftID = res->key;
        node->leftPos = res->pos;
        oram->WriteNode(node->key, node);
        Node* res2 = rightRotate(node);
        pos = res2->pos;
        return res2->key;
    }

    // Right Left Case
    if (balance < -1 && key < oram->ReadNode(node->rightID)->key) {
        //printf("AVLTree->insert: Right Left Case");
        auto res = rightRotate(oram->ReadNode(node->rightID));
        node->rightID = res->key;
        node->rightPos = res->pos;
        oram->WriteNode(node->key, node);
        auto res2 = leftRotate(node);
        pos = res2->pos;
        return res2->key;
    }

    /* return the (unchanged) node pointer */
    oram->WriteNode(node->key, node);
    //printf("Node with key(%s), (pos: %d), (value: %d) is inserted without Rotation", node->key.key,node->pos,node->value);
    return node->key;
}

Node* AVLTree::search(Node* head, Bid key) {
    //printf("AVLTree::start searching");

    if (head == NULL || head->key == empty_key)
        return head;

    head = oram->ReadNode(head->key, head->pos, head->pos);
    if (head->key > key) {
        return search(oram->ReadNode(head->leftID, head->leftPos, head->leftPos), key);
    } else if (head->key < key) {
        return search(oram->ReadNode(head->rightID, head->rightPos, head->rightPos), key);
    } else
        return head;
}

void AVLTree::batchSearch(Node* head, vector<Bid> keys, vector<Node*>* results) {
    if (head == NULL || head->key == empty_key) {
        return;
    }
    head = oram->ReadNode(head->key, head->pos, head->pos);
    bool getLeft = false, getRight = false;
    vector<Bid> leftkeys,rightkeys;
    for (Bid bid : keys) {
        if (head->key > bid) {
            getLeft = true;
            leftkeys.push_back(bid);
        }
        if (head->key < bid) {
            getRight = true;
            rightkeys.push_back(bid);
        }
        if (head->key == bid) {
            results->push_back(head);
        }
    }
    if (getLeft) {
        batchSearch(oram->ReadNode(head->leftID, head->leftPos, head->leftPos), leftkeys, results);
    }
    if (getRight) {
        batchSearch(oram->ReadNode(head->rightID, head->rightPos, head->rightPos), rightkeys, results);
    }
}

void AVLTree::startOperation(bool batchWrite) {
    oram->start(batchWrite);
}


void AVLTree::finishOperation(bool find, Bid& rootKey, unsigned int& rootPos) {
    oram->finalise(find, rootKey, rootPos);
}

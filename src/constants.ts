import { PrivateKey, PublicKey } from 'snarkyjs';

export {
  MAX_APPROVER_NUM,
  MAX_DESC_FIELD_NUM,
  EMPTY_PUBLICKEY,
  DUMMY_PRIVATEKEY,
  DUMMY_PUBLICKEY,
};

const MAX_APPROVER_NUM = 4;
const MAX_DESC_FIELD_NUM = 5;
const DUMMY_PRIVATEKEY = PrivateKey.fromBase58(
  'EKELNK85WAGkGDz8i8gbYky6AGkn2gbDk3rtFvV4R5yuVAM7uFhB'
);
const DUMMY_PUBLICKEY = DUMMY_PRIVATEKEY.toPublicKey();
const EMPTY_PUBLICKEY = PublicKey.empty();

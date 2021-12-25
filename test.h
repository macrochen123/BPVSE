/***
This is a test function set. The main purpose is to test the correctness of each key function.
*/

#ifndef _HEADER_TEST_H_
#define _HEADER_TEST_H_


/*test the hash function*/
void htest();
/*test the standard permutation function*/
void Etest();
/*test the transform function: int to char */
void IntCharTest();
//
void StrCharTest();
void SchemeTest();
void DBTest();
//void TimeTest();

/*
*test the time cost of each insert a <key, value> pair
*/
void T1insert();

//void TAes();
void ZSchemeETest();

void randomTest();

int MSchemeTest();

//

void SschemeTest();
void STimeTest();


void HschemeTest();
void HTimeTest();

//
void CschemeTest();
void CTimeTest();
#endif
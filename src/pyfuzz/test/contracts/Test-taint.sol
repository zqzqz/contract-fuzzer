pragma solidity ^0.4.24;

contract Test {
    address owner;
    uint num1;
    uint num2;
    mapping(address => uint) payments;

    function test1(uint a, uint b) public payable {
        uint c=a;
        uint d;
	uint e;
	uint f;
	uint g;
	for (uint i=0; i<4; i++){
	    d=a+b;
            e=c;
            if (b>num1) {
		f=e+a;
		owner = msg.sender;
	    }
            g=d;
	}
        num1 = f;
    }
    
    function test2(uint a, uint b, uint c) public payable {
	uint tmp;
	uint i=c;
	uint j;
	if (c>5) {
	    tmp = a;
	    num1 = tmp;
		num2 = a;
	}
	else {
	    tmp = b;
	    num2 = tmp;
	    j = a+b;
	}
    }

   function test3(uint a, uint b, uint c) public payable {
	while (a<4) {
	    num1 = b+2;
	}
   }

}
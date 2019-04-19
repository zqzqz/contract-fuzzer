pragma solidity ^0.4.24;

contract Test {
    address owner;
    mapping(address => uint) payments;

    function test1(uint a) public payable {
        uint b=0;
	for (uint i=0; i<4; i++){
	    b=i;
            if (b>2) {
		b++;
	    }
	}
    }

    function test2() public {
	uint i=0;
        while(i<4){
	    i++;
	}
    }
    
    function test3() public {
	uint a=0;
	if (a>0) {
	    a--;
	}
	else if (a<0) {
	    a++;
	}
	else {
	    a=10;
	}
	a=5;	
    }

    function test4() public {
	uint a=0;
	if (a>0) {
	    a--;
	    if (a<1) {
		a=2;
	    }
	}
	else {
	    a=10;
	}
	a=1;
    }
}
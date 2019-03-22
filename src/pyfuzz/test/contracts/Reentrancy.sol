pragma solidity ^0.4.24;

contract Test{
    bool flag;

    constructor() public {
        flag = true;
    }

    function Reentrancy() public {
        require(msg.sender.call.value(100)());
        flag = false;
    }
}
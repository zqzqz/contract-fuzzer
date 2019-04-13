pragma solidity ^0.4.24;

contract Test {
    function BlockNumberDependency() public {
        uint value = block.number + 10000;
        msg.sender.transfer(value);
    }
}
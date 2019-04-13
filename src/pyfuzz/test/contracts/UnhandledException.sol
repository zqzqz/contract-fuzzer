pragma solidity ^0.4.24;

contract Test {
    uint a;

    function UnhandledException() public {
        msg.sender.send(0xff);
    }
}
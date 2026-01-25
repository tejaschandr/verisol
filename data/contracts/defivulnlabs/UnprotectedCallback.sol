// SPDX-License-Identifier: MIT
// Source: https://github.com/SunWeb3Sec/DeFiVulnLabs
// Vulnerability: Unprotected Callback (ERC721 SafeMint)
pragma solidity ^0.8.18;

/*
Name: Unprotected Callback - ERC721 SafeMint Reentrancy

Description:
The _safeMint function calls onERC721Received on the recipient, which can be
exploited to bypass minting limits. The attacker's callback function can
mint additional tokens before the first mint completes.

Mitigation:
Use reentrancy guard and check-effects-interactions pattern.
*/

// Simplified ERC721 with vulnerable safeMint
contract MaxMint721 {
    uint256 public MAX_PER_USER = 10;
    uint256 private _tokenId;

    mapping(address => uint256) public balanceOf;
    mapping(uint256 => address) public ownerOf;

    function mint(uint256 amount) external {
        require(
            balanceOf[msg.sender] + amount <= MAX_PER_USER,
            "exceed max per user"
        );

        for (uint256 i = 0; i < amount; i++) {
            uint256 tokenId = _tokenId++;

            // VULNERABILITY: Callback before state update
            if (msg.sender.code.length > 0) {
                (bool success, ) = msg.sender.call(
                    abi.encodeWithSignature(
                        "onERC721Received(address,address,uint256,bytes)",
                        address(this),
                        address(0),
                        tokenId,
                        ""
                    )
                );
                require(success, "callback failed");
            }

            ownerOf[tokenId] = msg.sender;
            balanceOf[msg.sender]++;
        }
    }
}

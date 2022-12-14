import assert from "assert";
import * as anchor from "@project-serum/anchor";
import { Program } from "@project-serum/anchor";
import * as spl from "@solana/spl-token";
import { Defender } from "../target/types/defender";

interface PDAParameters {
  escrowWalletKey: anchor.web3.PublicKey;
  stateKey: anchor.web3.PublicKey;
  escrowBump: number;
  stateBump: number;
  idx: anchor.BN;
}

describe("defender", () => {
  // Configure the client to use the local cluster.
  const provider = anchor.Provider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.Defender as Program<Defender>;

  let mintAddress: anchor.web3.PublicKey;
  let backend: anchor.web3.Keypair;
  let alice: anchor.web3.Keypair;
  let aliceWallet: anchor.web3.PublicKey;
  let bobWallet: anchor.web3.PublicKey;
  let bob: anchor.web3.Keypair;

  let pda: PDAParameters;

  const getPdaParams = async (
    _connection: anchor.web3.Connection,
    alice: anchor.web3.PublicKey,
    mint: anchor.web3.PublicKey
  ): Promise<PDAParameters> => {
    const uid = new anchor.BN(parseInt((Date.now() / 1000).toString()));
    const uidBuffer = uid.toBuffer("le", 8);

    let [statePubKey, stateBump] =
      await anchor.web3.PublicKey.findProgramAddress(
        [Buffer.from("state"), alice.toBuffer(), mint.toBuffer(), uidBuffer],
        program.programId
      );
    let [walletPubKey, walletBump] =
      await anchor.web3.PublicKey.findProgramAddress(
        [Buffer.from("wallet"), alice.toBuffer(), mint.toBuffer(), uidBuffer],
        program.programId
      );
    console.log("Created PDA params");
    return {
      idx: uid,
      escrowBump: walletBump,
      escrowWalletKey: walletPubKey,
      stateBump,
      stateKey: statePubKey,
    };
  };

  const createMint = async (
    _connection: anchor.web3.Connection
  ): Promise<anchor.web3.PublicKey> => {
    const tokenMint = new anchor.web3.Keypair();
    const lamportsForMint =
      await provider.connection.getMinimumBalanceForRentExemption(
        spl.MintLayout.span
      );
    let tx = new anchor.web3.Transaction();

    // Allocate mint
    tx.add(
      anchor.web3.SystemProgram.createAccount({
        programId: spl.TOKEN_PROGRAM_ID,
        space: spl.MintLayout.span,
        fromPubkey: provider.wallet.publicKey,
        newAccountPubkey: tokenMint.publicKey,
        lamports: lamportsForMint,
      })
    );
    // Allocate wallet account
    tx.add(
      spl.Token.createInitMintInstruction(
        spl.TOKEN_PROGRAM_ID,
        tokenMint.publicKey,
        6,
        provider.wallet.publicKey,
        provider.wallet.publicKey
      )
    );
    const signature = await provider.send(tx, [tokenMint]);

    console.log(
      `[${tokenMint.publicKey}] Created new mint account at ${signature}`
    );
    return tokenMint.publicKey;
  };

  const createUserAndAssociatedWallet = async (
    _connection: anchor.web3.Connection,
    mint?: anchor.web3.PublicKey,
    backendSecretKey?: Uint8Array
  ): Promise<[anchor.web3.Keypair, anchor.web3.PublicKey | undefined]> => {
    const user = backendSecretKey
      ? anchor.web3.Keypair.fromSecretKey(backendSecretKey)
      : new anchor.web3.Keypair();
    let userAssociatedTokenAccount: anchor.web3.PublicKey | undefined =
      undefined;

    // Fund user with some SOL
    let txFund = new anchor.web3.Transaction();
    txFund.add(
      anchor.web3.SystemProgram.transfer({
        fromPubkey: provider.wallet.publicKey,
        toPubkey: user.publicKey,
        lamports: 5 * anchor.web3.LAMPORTS_PER_SOL,
      })
    );
    const sigTxFund = await provider.send(txFund);
    console.log(
      `[${user.publicKey.toBase58()}] Funded new account with 5 SOL: ${sigTxFund}`
    );

    if (mint) {
      // Create a token account for the user and mint some tokens
      userAssociatedTokenAccount = await spl.Token.getAssociatedTokenAddress(
        spl.ASSOCIATED_TOKEN_PROGRAM_ID,
        spl.TOKEN_PROGRAM_ID,
        mint,
        user.publicKey
      );

      const txFundTokenAccount = new anchor.web3.Transaction();
      txFundTokenAccount.add(
        spl.Token.createAssociatedTokenAccountInstruction(
          spl.ASSOCIATED_TOKEN_PROGRAM_ID,
          spl.TOKEN_PROGRAM_ID,
          mint,
          userAssociatedTokenAccount,
          user.publicKey,
          user.publicKey
        )
      );
      txFundTokenAccount.add(
        spl.Token.createMintToInstruction(
          spl.TOKEN_PROGRAM_ID,
          mint,
          userAssociatedTokenAccount,
          provider.wallet.publicKey,
          [],
          1337000000
        )
      );
      const txFundTokenSig = await provider.send(txFundTokenAccount, [user]);
      console.log(
        `[${userAssociatedTokenAccount.toBase58()}] New associated account for mint ${mint.toBase58()}: ${txFundTokenSig}`
      );
    }
    return [user, userAssociatedTokenAccount];
  };

  const readAccount = async (
    accountPublicKey: anchor.web3.PublicKey,
    provider: anchor.Provider
  ): Promise<[spl.AccountInfo, string]> => {
    const tokenInfoLol = await provider.connection.getAccountInfo(
      accountPublicKey
    );
    const data = Buffer.from(tokenInfoLol.data);
    const accountInfo: spl.AccountInfo = spl.AccountLayout.decode(data);

    const amount = (accountInfo.amount as any as Buffer).readBigUInt64LE();
    return [accountInfo, amount.toString()];
  };

  // const readMint = async (
  //   mintPublicKey: anchor.web3.PublicKey,
  //   provider: anchor.Provider
  // ): Promise<spl.MintInfo> => {
  //   const tokenInfo = await provider.connection.getAccountInfo(mintPublicKey);
  //   const data = Buffer.from(tokenInfo.data);
  //   const accountInfo = spl.MintLayout.decode(data);
  //   return {
  //     ...accountInfo,
  //     mintAuthority:
  //       accountInfo.mintAuthority == null
  //         ? null
  //         : anchor.web3.PublicKey.decode(accountInfo.mintAuthority),
  //     freezeAuthority:
  //       accountInfo.freezeAuthority == null
  //         ? null
  //         : anchor.web3.PublicKey.decode(accountInfo.freezeAuthority),
  //   };
  // };

  beforeEach(async () => {
    mintAddress = await createMint(provider.connection);
    const backendKey = Uint8Array.from([
      144, 247, 101, 216, 217, 74, 146, 124, 188, 130, 198, 201, 95, 115, 70,
      28, 91, 48, 180, 87, 222, 168, 5, 197, 197, 156, 178, 231, 122, 87, 74,
      87, 47, 200, 72, 129, 31, 62, 119, 90, 57, 252, 240, 34, 145, 192, 141,
      109, 173, 173, 114, 196, 154, 194, 157, 116, 205, 124, 93, 252, 35, 148,
      185, 171,
    ]);
    [alice, aliceWallet] = await createUserAndAssociatedWallet(
      provider.connection,
      mintAddress
    );
    [bob, bobWallet] = await createUserAndAssociatedWallet(
      provider.connection,
      mintAddress
    );
    [backend] = await createUserAndAssociatedWallet(
      provider.connection,
      mintAddress,
      backendKey
    );

    // // Generate bob without associated token account
    // [bob,] = await createUserAndAssociatedWallet(provider.connection);

    pda = await getPdaParams(provider.connection, alice.publicKey, mintAddress);
  });

  it("can initialize a vault for Alice", async () => {
    const [, aliceBalancePre] = await readAccount(aliceWallet, provider);
    assert.equal(aliceBalancePre, "1337000000");

    const amount = new anchor.BN(10000000);

    // Initialize vault account and fund the account
    await program.rpc.initializeNewVault(
      pda.idx,
      pda.stateBump,
      pda.escrowBump,
      amount,
      {
        accounts: {
          applicationState: pda.stateKey,
          escrowWalletState: pda.escrowWalletKey,
          mintOfTokenBeingSent: mintAddress,
          userSending: alice.publicKey,
          walletToWithdrawFrom: aliceWallet,

          systemProgram: anchor.web3.SystemProgram.programId,
          rent: anchor.web3.SYSVAR_RENT_PUBKEY,
          tokenProgram: spl.TOKEN_PROGRAM_ID,
        },
        signers: [alice],
      }
    );
    console.log(`Initialized a new vault for Alice`);

    // Assert that Alice's account balance is the same, and the escrow's balance is 0
    const [, aliceBalanceInit] = await readAccount(aliceWallet, provider);
    assert.equal(aliceBalanceInit, "1337000000");
    const [, escrowBalanceInit] = await readAccount(
      pda.escrowWalletKey,
      provider
    );
    assert.equal(escrowBalanceInit, "0");

    // Deposit 10 tokens from Alice's account to the escrow
    await program.rpc.deposit(pda.idx, pda.stateBump, pda.escrowBump, amount, {
      accounts: {
        applicationState: pda.stateKey,
        escrowWalletState: pda.escrowWalletKey,
        mintOfTokenBeingSent: mintAddress,
        userSending: alice.publicKey,
        walletToWithdrawFrom: aliceWallet,

        systemProgram: anchor.web3.SystemProgram.programId,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        tokenProgram: spl.TOKEN_PROGRAM_ID,
      },
      signers: [alice],
    });

    // Assert that 10 tokens were moved from Alice's account to the escrow.
    const [, aliceBalancePost] = await readAccount(aliceWallet, provider);
    assert.equal(aliceBalancePost, "1327000000");
    const [, escrowBalancePost] = await readAccount(
      pda.escrowWalletKey,
      provider
    );
    assert.equal(escrowBalancePost, "10000000");
  });

  it("can send vault funds to Bob", async () => {
    const [, aliceBalancePre] = await readAccount(aliceWallet, provider);
    assert.equal(aliceBalancePre, "1337000000");

    const amount = new anchor.BN(20000000);

    // Initialize vault account and fund the account
    await program.rpc.initializeNewVault(
      pda.idx,
      pda.stateBump,
      pda.escrowBump,
      amount,
      {
        accounts: {
          applicationState: pda.stateKey,
          escrowWalletState: pda.escrowWalletKey,
          mintOfTokenBeingSent: mintAddress,
          userSending: alice.publicKey,
          walletToWithdrawFrom: aliceWallet,

          systemProgram: anchor.web3.SystemProgram.programId,
          rent: anchor.web3.SYSVAR_RENT_PUBKEY,
          tokenProgram: spl.TOKEN_PROGRAM_ID,
        },
        signers: [alice],
      }
    );
    console.log(`Initialized a new vault for Alice`);

    await program.rpc.deposit(pda.idx, pda.stateBump, pda.escrowBump, amount, {
      accounts: {
        applicationState: pda.stateKey,
        escrowWalletState: pda.escrowWalletKey,
        mintOfTokenBeingSent: mintAddress,
        userSending: alice.publicKey,
        walletToWithdrawFrom: aliceWallet,

        systemProgram: anchor.web3.SystemProgram.programId,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        tokenProgram: spl.TOKEN_PROGRAM_ID,
      },
      signers: [alice],
    });
    // Assert that 20 tokens were moved from Alice's account to the escrow.
    const [, aliceBalancePost] = await readAccount(aliceWallet, provider);
    assert.equal(aliceBalancePost, "1317000000");
    const [, escrowBalancePost] = await readAccount(
      pda.escrowWalletKey,
      provider
    );
    assert.equal(escrowBalancePost, "20000000");

    // Verify Bob's initial balance
    const [, b] = await readAccount(bobWallet, provider);
    assert.equal(b, "1337000000");

    // Send 10 tokens from vault to Bob
    const sendAmount = new anchor.BN(10000000);
    await program.rpc.completeTransaction(
      pda.idx,
      pda.stateBump,
      pda.escrowBump,
      sendAmount,
      {
        accounts: {
          applicationState: pda.stateKey,
          escrowWalletState: pda.escrowWalletKey,
          mintOfTokenBeingSent: mintAddress,
          userSending: alice.publicKey,
          userReceiving: bob.publicKey,
          backendAccount: backend.publicKey,
          walletToDepositTo: bobWallet,

          systemProgram: anchor.web3.SystemProgram.programId,
          rent: anchor.web3.SYSVAR_RENT_PUBKEY,
          tokenProgram: spl.TOKEN_PROGRAM_ID,
          associatedTokenProgram: spl.ASSOCIATED_TOKEN_PROGRAM_ID,
        },
        signers: [alice, backend],
      }
    );

    // Assert that 10 tokens were sent to Bob.
    const [, bobBalance] = await readAccount(bobWallet, provider);
    assert.equal(bobBalance, "1347000000");

    // Send another 10 tokens to Bob
    await program.rpc.completeTransaction(
      pda.idx,
      pda.stateBump,
      pda.escrowBump,
      sendAmount,
      {
        accounts: {
          applicationState: pda.stateKey,
          escrowWalletState: pda.escrowWalletKey,
          mintOfTokenBeingSent: mintAddress,
          userSending: alice.publicKey,
          userReceiving: bob.publicKey,
          backendAccount: backend.publicKey,
          walletToDepositTo: bobWallet,

          systemProgram: anchor.web3.SystemProgram.programId,
          rent: anchor.web3.SYSVAR_RENT_PUBKEY,
          tokenProgram: spl.TOKEN_PROGRAM_ID,
          associatedTokenProgram: spl.ASSOCIATED_TOKEN_PROGRAM_ID,
        },
        signers: [alice, backend],
      }
    );

    // Assert that 10 tokens were sent to Bob.
    const [, bobBalance2] = await readAccount(bobWallet, provider);
    assert.equal(bobBalance2, "1357000000");
    const [, escrowBalancePost2] = await readAccount(
      pda.escrowWalletKey,
      provider
    );
    assert.equal(escrowBalancePost2, "0");

    // Fail when vault is empty
    try {
      assert.throws(async () => {
        await program.rpc.completeTransaction(
          pda.idx,
          pda.stateBump,
          pda.escrowBump,
          sendAmount,
          {
            accounts: {
              applicationState: pda.stateKey,
              escrowWalletState: pda.escrowWalletKey,
              mintOfTokenBeingSent: mintAddress,
              userSending: alice.publicKey,
              userReceiving: bob.publicKey,
              backendAccount: backend.publicKey,
              walletToDepositTo: bobWallet,

              systemProgram: anchor.web3.SystemProgram.programId,
              rent: anchor.web3.SYSVAR_RENT_PUBKEY,
              tokenProgram: spl.TOKEN_PROGRAM_ID,
              associatedTokenProgram: spl.ASSOCIATED_TOKEN_PROGRAM_ID,
            },
            signers: [alice, backend],
          }
        );
      });
      return assert.fail("Transaction should fail with empty escrow");
    } catch (e) {}

    // Verify that transaction fails with only Alice's signature
    try {
      await program.rpc.completeTransaction(
        pda.idx,
        pda.stateBump,
        pda.escrowBump,
        sendAmount,
        {
          accounts: {
            applicationState: pda.stateKey,
            escrowWalletState: pda.escrowWalletKey,
            mintOfTokenBeingSent: mintAddress,
            userSending: alice.publicKey,
            userReceiving: bob.publicKey,
            backendAccount: backend.publicKey,
            walletToDepositTo: bobWallet,

            systemProgram: anchor.web3.SystemProgram.programId,
            rent: anchor.web3.SYSVAR_RENT_PUBKEY,
            tokenProgram: spl.TOKEN_PROGRAM_ID,
            associatedTokenProgram: spl.ASSOCIATED_TOKEN_PROGRAM_ID,
          },
          signers: [alice],
        }
      );
      return assert.fail("Transaction should fail without two signatures");
    } catch (e) {
      assert.equal(e.message, "Signature verification failed");
    }

    // Verify that transaction fails with Bob's signature
    try {
      await program.rpc.completeTransaction(
        pda.idx,
        pda.stateBump,
        pda.escrowBump,
        sendAmount,
        {
          accounts: {
            applicationState: pda.stateKey,
            escrowWalletState: pda.escrowWalletKey,
            mintOfTokenBeingSent: mintAddress,
            userSending: alice.publicKey,
            userReceiving: bob.publicKey,
            backendAccount: backend.publicKey,
            walletToDepositTo: bobWallet,

            systemProgram: anchor.web3.SystemProgram.programId,
            rent: anchor.web3.SYSVAR_RENT_PUBKEY,
            tokenProgram: spl.TOKEN_PROGRAM_ID,
            associatedTokenProgram: spl.ASSOCIATED_TOKEN_PROGRAM_ID,
          },
          signers: [bob, backend],
        }
      );
      return assert.fail("Transaction should fail without Alice's signature");
    } catch (e) {
      assert.equal(e.message, "unknown signer: " + bob.publicKey);
    }
  });

  it("can withdraw funds after they are deposited", async () => {
    const [, aliceBalancePre] = await readAccount(aliceWallet, provider);
    assert.equal(aliceBalancePre, "1337000000");

    const amount = new anchor.BN(20000000);

    // Initialize vault account and fund the account
    await program.rpc.initializeNewVault(
      pda.idx,
      pda.stateBump,
      pda.escrowBump,
      amount,
      {
        accounts: {
          applicationState: pda.stateKey,
          escrowWalletState: pda.escrowWalletKey,
          mintOfTokenBeingSent: mintAddress,
          userSending: alice.publicKey,
          walletToWithdrawFrom: aliceWallet,

          systemProgram: anchor.web3.SystemProgram.programId,
          rent: anchor.web3.SYSVAR_RENT_PUBKEY,
          tokenProgram: spl.TOKEN_PROGRAM_ID,
        },
        signers: [alice],
      }
    );

    await program.rpc.deposit(pda.idx, pda.stateBump, pda.escrowBump, amount, {
      accounts: {
        applicationState: pda.stateKey,
        escrowWalletState: pda.escrowWalletKey,
        mintOfTokenBeingSent: mintAddress,
        userSending: alice.publicKey,
        walletToWithdrawFrom: aliceWallet,

        systemProgram: anchor.web3.SystemProgram.programId,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        tokenProgram: spl.TOKEN_PROGRAM_ID,
      },
      signers: [alice],
    });
    console.log(`Initialized a new vault for Alice`);

    // Assert that 20 tokens were moved from Alice's account to the escrow.
    const [, aliceBalancePost] = await readAccount(aliceWallet, provider);
    assert.equal(aliceBalancePost, "1317000000");
    const [, escrowBalancePost] = await readAccount(
      pda.escrowWalletKey,
      provider
    );
    assert.equal(escrowBalancePost, "20000000");

    // Withdraw the funds back
    await program.rpc.withdraw(pda.idx, pda.stateBump, pda.escrowBump, amount, {
      accounts: {
        applicationState: pda.stateKey,
        escrowWalletState: pda.escrowWalletKey,
        mintOfTokenBeingSent: mintAddress,
        userSending: alice.publicKey,
        refundWallet: aliceWallet,

        systemProgram: anchor.web3.SystemProgram.programId,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        tokenProgram: spl.TOKEN_PROGRAM_ID,
      },
      signers: [alice],
    });

    // Assert that 20 tokens were sent back.
    const [, aliceBalanceRefund] = await readAccount(aliceWallet, provider);
    assert.equal(aliceBalanceRefund, "1337000000");
    const [, escrowBalancePost2] = await readAccount(
      pda.escrowWalletKey,
      provider
    );
    assert.equal(escrowBalancePost2, "0");

    // Fail when vault is empty
    try {
      assert.throws(async () => {
        await program.rpc.withdraw(
          pda.idx,
          pda.stateBump,
          pda.escrowBump,
          amount,
          {
            accounts: {
              applicationState: pda.stateKey,
              escrowWalletState: pda.escrowWalletKey,
              mintOfTokenBeingSent: mintAddress,
              userSending: alice.publicKey,
              refundWallet: aliceWallet,

              systemProgram: anchor.web3.SystemProgram.programId,
              rent: anchor.web3.SYSVAR_RENT_PUBKEY,
              tokenProgram: spl.TOKEN_PROGRAM_ID,
            },
            signers: [alice],
          }
        );
      });
      return assert.fail("Transaction should fail with empty escrow");
    } catch (e) {}
  });
});

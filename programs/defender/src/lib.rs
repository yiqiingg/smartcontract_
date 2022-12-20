use anchor_lang::prelude::*;
use anchor_spl::{associated_token::AssociatedToken, token::{Mint, Token, TokenAccount, Transfer}};

declare_id!("5Nh6B8mvMuHkn9bgB2Sh59zypRLVcHNCe5bBQyE1b2Ey");

// #[error_code]
// pub enum ErrorCode {
//     #[msg("Wallet to withdraw from is not owned by owner")]
//     WalletToWithdrawFromInvalid,
//     #[msg("State index is inconsistent")]
//     InvalidStateIdx,
//     #[msg("Delegate is not set correctly")]
//     DelegateNotSetCorrectly,
//     #[msg("Stage is invalid")]
//     StageInvalid,
// }

// 
/// A small utility function that allows us to transfer funds out of the Escrow.
///
/// # Arguments
///
/// * `user_sending` - Alice's account
/// * `user_receiving` - Bob's account
/// * `mint_of_token_being_sent` - The mint of the token being held in escrow
/// * `escrow_wallet` - The escrow Token account
/// * `application_idx` - The primary key (timestamp) of the instance
/// * `state` - the application state public key (PDA)
/// * `state_bump` - the application state public key (PDA) bump
/// * `token_program` - the token program address
/// * `destination_wallet` - The public key of the destination address (where to send funds)
/// * `amount` - the amount of `mint_of_token_being_sent` that is sent from `escrow_wallet` to `destination_wallet`
///
fn transfer_escrow_out<'info>(
    user_sending: AccountInfo<'info>,
    mint_of_token_being_sent: AccountInfo<'info>,
    escrow_wallet: &mut Account<'info, TokenAccount>,
    application_idx: u64,
    state: AccountInfo<'info>,
    state_bump: u8,
    token_program: AccountInfo<'info>,
    destination_wallet: AccountInfo<'info>,
    amount: u64
) -> Result<()> {
    let bump_vector = state_bump.to_le_bytes();
    let mint_of_token_being_sent_pk = mint_of_token_being_sent.key().clone();
    let application_idx_bytes = application_idx.to_le_bytes();
    let inner = vec![
        b"state".as_ref(),
        user_sending.key.as_ref(),
        mint_of_token_being_sent_pk.as_ref(), 
        application_idx_bytes.as_ref(),
        bump_vector.as_ref(),
    ];
    let outer = vec![inner.as_slice()];

    msg!("start transfer");
    let transfer_instruction = Transfer{
        from: escrow_wallet.to_account_info(),
        to: destination_wallet,
        authority: state.to_account_info(),
    };
    let cpi_ctx = CpiContext::new_with_signer(
        token_program.to_account_info(),
        transfer_instruction,
        outer.as_slice(),
    );
    anchor_spl::token::transfer(cpi_ctx, amount)?;
    msg!("transfer succeess");

    Ok(())
}

#[program]
pub mod defender {

    use anchor_spl::token::Transfer;
    use super::*;

    pub fn initialize_new_vault(ctx: Context<InitializeNewVault>, application_idx: u64, _state_bump: u8, _wallet_bump: u8, _amount: u64) -> Result<()> {
        // Set the state attributes
        let state = &mut ctx.accounts.application_state;
        state.idx = application_idx;
        state.user_sending = ctx.accounts.user_sending.key().clone();
        state.mint_of_token_being_sent = ctx.accounts.mint_of_token_being_sent.key().clone();
        state.escrow_wallet = ctx.accounts.escrow_wallet_state.key().clone();

        msg!("Initialized new Defender instance for Alice: {}", ctx.accounts.user_sending.key());
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, application_idx: u64, state_bump: u8, _wallet_bump: u8, amount: u64) -> Result<()> {
        // Compute signer seeds for state PDA
        let bump_vector = state_bump.to_le_bytes();
        let mint_of_token_being_sent_pk = ctx.accounts.mint_of_token_being_sent.key().clone();
        let application_idx_bytes = application_idx.to_le_bytes();
        let inner = vec![
            b"state".as_ref(),
            ctx.accounts.user_sending.key.as_ref(),
            mint_of_token_being_sent_pk.as_ref(), 
            application_idx_bytes.as_ref(),
            bump_vector.as_ref(),
        ];
        let outer = vec![inner.as_slice()];

        // Transfer funds from Alice's wallet to the vault
        let transfer_instruction = Transfer{
            from: ctx.accounts.wallet_to_withdraw_from.to_account_info(),
            to: ctx.accounts.escrow_wallet_state.to_account_info(),
            authority: ctx.accounts.user_sending.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            transfer_instruction,
            outer.as_slice(),
        );
        anchor_spl::token::transfer(cpi_ctx, amount)?;

        Ok(())
    }

    pub fn complete_transaction(ctx: Context<CompleteTransaction>, application_idx: u64, state_bump: u8, _wallet_bump: u8, amount: u64) -> Result<()> {
        transfer_escrow_out(
            ctx.accounts.user_sending.to_account_info(),
            ctx.accounts.mint_of_token_being_sent.to_account_info(),
            &mut ctx.accounts.escrow_wallet_state,
            application_idx,
            ctx.accounts.application_state.to_account_info(),
            state_bump,
            ctx.accounts.token_program.to_account_info(),
            ctx.accounts.wallet_to_deposit_to.to_account_info(),
            amount
        )?;
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, application_idx: u64, state_bump: u8, _wallet_bump: u8, amount: u64) -> Result<()> {
        transfer_escrow_out(
            ctx.accounts.user_sending.to_account_info(),
            ctx.accounts.mint_of_token_being_sent.to_account_info(),
            &mut ctx.accounts.escrow_wallet_state,
            application_idx,
            ctx.accounts.application_state.to_account_info(),
            state_bump,
            ctx.accounts.token_program.to_account_info(),
            ctx.accounts.refund_wallet.to_account_info(),
            amount,
        )?;
        Ok(())
    }

}

// 1 State account instance == 1 Defender instance
#[account]
#[derive(Default)]
pub struct State {

    // A primary key that allows us to derive other important accounts
    idx: u64,
    
    // Owner of the vault PDA
    user_sending: Pubkey,

    // The Mint of the token that owner wants to send
    mint_of_token_being_sent: Pubkey,

    // The escrow wallet
    escrow_wallet: Pubkey
}

#[derive(Accounts)]
#[instruction(application_idx: u64, state_bump: u8, wallet_bump: u8)]
pub struct InitializeNewVault<'info> {

    // Derived PDAs
    #[account(
        init,
        payer = user_sending,
        seeds=[b"state".as_ref(), user_sending.key().as_ref(), mint_of_token_being_sent.key().as_ref(), application_idx.to_le_bytes().as_ref()],
        bump,
        space = 8 + 104
    )]
    application_state: Account<'info, State>,
    #[account(
        init,
        payer = user_sending,
        seeds=[b"wallet".as_ref(), user_sending.key().as_ref(), mint_of_token_being_sent.key().as_ref(), application_idx.to_le_bytes().as_ref()],
        bump,
        token::mint=mint_of_token_being_sent,
        token::authority=application_state,
    )]
    escrow_wallet_state: Account<'info, TokenAccount>,

    // Users and accounts in the system
    #[account(mut)]
    user_sending: Signer<'info>,                     // Alice
    mint_of_token_being_sent: Account<'info, Mint>,  // USDC

    // Alice's USDC wallet that has already approved the escrow wallet
    #[account(
        mut,
        constraint=wallet_to_withdraw_from.owner == user_sending.key(),
        constraint=wallet_to_withdraw_from.mint == mint_of_token_being_sent.key()
    )]
    wallet_to_withdraw_from: Account<'info, TokenAccount>,

    // Application level accounts
    system_program: Program<'info, System>,
    token_program: Program<'info, Token>,
    rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(application_idx: u64, state_bump: u8, wallet_bump: u8)]
pub struct Deposit<'info> {
    // Derived PDAs
    #[account(
        mut,
        seeds=[b"state".as_ref(), user_sending.key().as_ref(), mint_of_token_being_sent.key().as_ref(), application_idx.to_le_bytes().as_ref()],
        bump = state_bump,
    )]
    application_state: Account<'info, State>,
    #[account(
        mut,
        seeds=[b"wallet".as_ref(), user_sending.key().as_ref(), mint_of_token_being_sent.key().as_ref(), application_idx.to_le_bytes().as_ref()],
        bump = wallet_bump,
    )]
    escrow_wallet_state: Account<'info, TokenAccount>,

    // Users and accounts in the system
    #[account(mut)]
    user_sending: Signer<'info>,                     // Alice
    mint_of_token_being_sent: Account<'info, Mint>,  // USDC

    // Alice's USDC wallet that has already approved the escrow wallet
    #[account(
        mut,
        constraint=wallet_to_withdraw_from.owner == user_sending.key(),
        constraint=wallet_to_withdraw_from.mint == mint_of_token_being_sent.key()
    )]
    wallet_to_withdraw_from: Account<'info, TokenAccount>,

    // Application level accounts
    system_program: Program<'info, System>,
    token_program: Program<'info, Token>,
    rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(application_idx: u64, state_bump: u8, wallet_bump: u8)]
pub struct CompleteTransaction<'info> {
    #[account(
        mut,
        seeds=[b"state".as_ref(), user_sending.key().as_ref(), mint_of_token_being_sent.key().as_ref(), application_idx.to_le_bytes().as_ref()],
        bump = state_bump,
        has_one = user_sending,
        has_one = mint_of_token_being_sent,
    )]
    application_state: Account<'info, State>,
    #[account(
        mut,
        seeds=[b"wallet".as_ref(), user_sending.key().as_ref(), mint_of_token_being_sent.key().as_ref(), application_idx.to_le_bytes().as_ref()],
        bump = wallet_bump,
    )]
    escrow_wallet_state: Account<'info, TokenAccount>,

    #[account(mut)]
    wallet_to_deposit_to: Account<'info, TokenAccount>,   // Bob's USDC wallet (will be initialized if it did not exist)

    // Users and accounts in the system
    #[account(mut)]
    user_sending: Signer<'info>,                     // Alice
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    user_receiving: AccountInfo<'info>,              // Bob
    #[account(mut)]
    backend_account: Signer<'info>,                  // Application backend signer
    mint_of_token_being_sent: Account<'info, Mint>,       // USDC

    // Application level accounts
    system_program: Program<'info, System>,
    token_program: Program<'info, Token>,
    associated_token_program: Program<'info, AssociatedToken>,
    rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(application_idx: u64, state_bump: u8, wallet_bump: u8)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds=[b"state".as_ref(), user_sending.key().as_ref(), mint_of_token_being_sent.key().as_ref(), application_idx.to_le_bytes().as_ref()],
        bump = state_bump,
        has_one = user_sending,
        has_one = mint_of_token_being_sent,
    )]
    application_state: Account<'info, State>,
    #[account(
        mut,
        seeds=[b"wallet".as_ref(), user_sending.key().as_ref(), mint_of_token_being_sent.key().as_ref(), application_idx.to_le_bytes().as_ref()],
        bump = wallet_bump,
    )]
    escrow_wallet_state: Account<'info, TokenAccount>,

    // Users and accounts in the system
    #[account(mut)]
    user_sending: Signer<'info>,
    mint_of_token_being_sent: Account<'info, Mint>,

    // Application level accounts
    system_program: Program<'info, System>,
    token_program: Program<'info, Token>,
    rent: Sysvar<'info, Rent>,

    // Wallet to deposit to
    #[account(
        mut,
        constraint=refund_wallet.owner == user_sending.key(),
        constraint=refund_wallet.mint == mint_of_token_being_sent.key()
    )]
    refund_wallet: Account<'info, TokenAccount>,
}
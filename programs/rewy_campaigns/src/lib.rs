use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount};
use anchor_lang::solana_program::instruction::Instruction;
use sha2::{Digest, Sha256};

declare_id!("BxvZ8gSjCMgKeZ6LLsWX9fGp7A39zLBQ7vcFx91NeNBD");


// [Enums and Structs unchanged]
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq)]
pub enum CampaignType {
    StakeForAction,
    StakeForCrowdsource,
    StakeForDistribution,
}

#[account]
pub struct RewyAIConfig {
    pub admin: Pubkey,        // REWY AI admin key (you control this)
    pub verifier_key: Pubkey, // Dynamic REWY AI verifier key
}

#[account]
pub struct Campaign {
    pub authority: Pubkey,
    pub pda: Pubkey,
    pub campaign_type: CampaignType,
    pub rewy_mint: Pubkey,
    pub rewy_stake_account: Pubkey,
    pub rewy_staked_amount: u64,
    pub airdrop_mint: Option<Pubkey>,
    pub airdrop_stake_account: Option<Pubkey>,
    pub airdrop_staked_amount: Option<u64>,
    pub expiry: Option<i64>,
    pub is_active: bool,
    pub metadata: String,
    pub content_hash: [u8; 32],
    pub contributions: u64,
    pub target_amount: Option<u64>,
    pub vesting_period: Option<i64>,
    pub launch_token_mint: Option<Pubkey>,
    pub stake_locked_until: Option<i64>,
    pub nonce: u64,
    pub rewy_reward_per_action: u64,
    pub airdrop_reward_per_action: Option<u64>,
    pub max_claims: Option<u64>,
    pub business_verifier_key: Option<Pubkey>, // Business-specific key
}

#[account]
pub struct Distribution {
    pub campaign_pda: Pubkey,
    pub code: String,
    pub rewy_amount: u64,
    pub airdrop_amount: Option<u64>,
    pub is_redeemed: bool,
    pub recipient: Option<Pubkey>,
}

// [Events and Errors unchanged]

// Events
#[event]
pub struct ClaimMade {
    pub campaign: Pubkey,
    pub user: Pubkey,
    pub rewy_amount: u64,
    pub airdrop_amount: Option<u64>,
    pub claims_remaining: Option<u64>,
}

#[event]
pub struct RewardsUpdated {
    pub campaign: Pubkey,
    pub rewy_reward: u64,
    pub airdrop_reward: Option<u64>,
    pub max_claims: Option<u64>,
}

#[event]
pub struct CampaignInitialized {
    pub campaign: Pubkey,
    pub authority: Pubkey,
    pub campaign_type: CampaignType,
}

#[event]
pub struct DistributionRedeemed {
    pub campaign: Pubkey,
    pub code: String,
    pub recipient: Pubkey,
}

// Errors
#[error_code]
pub enum ErrorCode {
    #[msg("Campaign is paused")]
    CampaignPaused,
    #[msg("Insufficient stake for operation")]
    InsufficientStake,
    #[msg("Insufficient stake for reward update")]
    InsufficientStakeForUpdate,
    #[msg("Campaign has expired")]
    CampaignExpired,
    #[msg("Invalid proof signature")]
    InvalidProof,
    #[msg("Invalid campaign type")]
    InvalidType,
    #[msg("Max claims reached")]
    MaxClaimsReached,
    #[msg("Distribution already redeemed")]
    AlreadyRedeemed,
    #[msg("No airdrop configured")]
    NoAirdropConfigured,
    #[msg("Max claims cannot be set below current claims")]
    MaxClaimsTooLow,
    #[msg("Stake is still locked")]
    StakeLocked,
    #[msg("Target amount not met")]
    TargetNotMet,
    #[msg("Verifier key is missing")]
    VerifierKeyMissing,
}

// Accounts Contexts
#[derive(Accounts)]
#[instruction(metadata: String)]
pub struct InitializeCampaign<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 32 + 1 + 32 + 32 + 8 + 32 + 32 + 8 + 8 + 1 + 200 + 32 + 8 + 8 + 8 + 32 + 8 + 8 + 8 + 32,
        seeds = [b"campaign", authority.key().as_ref(), metadata.as_bytes()],
        bump
    )]
    pub campaign: Account<'info, Campaign>,
    #[account(
        init,
        payer = authority,
        token::mint = rewy_mint,
        token::authority = campaign,
        seeds = [b"rewy_stake", campaign.key().as_ref()],
        bump
    )]
    pub rewy_stake_account: Account<'info, TokenAccount>,
    #[account(
        init_if_needed,
        payer = authority,
        token::mint = airdrop_mint,
        token::authority = campaign,
        seeds = [b"airdrop_stake", campaign.key().as_ref()],
        bump
    )]
    pub airdrop_stake_account: Option<Account<'info, TokenAccount>>,
    pub rewy_mint: Account<'info, Mint>,
    pub airdrop_mint: Option<Account<'info, Mint>>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
}


#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + 32 + 32,
        seeds = [b"rewy_ai_config"],
        bump
    )]
    pub config: Account<'info, RewyAIConfig>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateVerifierKey<'info> {
    #[account(
        mut,
        has_one = admin,
        seeds = [b"rewy_ai_config"],
        bump
    )]
    pub config: Account<'info, RewyAIConfig>,
    pub admin: Signer<'info>,
}


#[derive(Accounts)]
pub struct RedeemVoucher<'info> {
    #[account(mut, has_one = rewy_stake_account, constraint = campaign.campaign_type == CampaignType::StakeForAction)]
    pub campaign: Account<'info, Campaign>,
    #[account(mut)]
    pub rewy_stake_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub airdrop_stake_account: Option<Account<'info, TokenAccount>>,
    /// CHECK: This is the user's wallet receiving tokens, verified by Ed25519 signature
    #[account(mut)]
    pub user_wallet: AccountInfo<'info>,
    pub token_program: Program<'info, Token>,
    pub clock: Sysvar<'info, Clock>,
    /// CHECK: This is the instructions sysvar for Ed25519 verification
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instructions: UncheckedAccount<'info>,
    #[account(seeds = [b"rewy_ai_config"], bump)]
    pub config: Account<'info, RewyAIConfig>,
}

#[derive(Accounts)]
#[instruction(code: String)]
pub struct CreateDistribution<'info> {
    #[account(mut, has_one = authority)]
    pub campaign: Account<'info, Campaign>,
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 64 + 8 + 8 + 1 + 32,
        seeds = [b"distribution", campaign.key().as_ref(), code.as_bytes()],
        bump
    )]
    pub distribution: Account<'info, Distribution>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct StakeRewards<'info> {
    #[account(mut, has_one = authority)]
    pub campaign: Account<'info, Campaign>,
    #[account(mut, seeds = [b"rewy_stake", campaign.key().as_ref()], bump)]
    pub rewy_stake_account: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"airdrop_stake", campaign.key().as_ref()], bump)]
    pub airdrop_stake_account: Option<Account<'info, TokenAccount>>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct UnstakeRewards<'info> {
    #[account(mut, has_one = authority)]
    pub campaign: Account<'info, Campaign>,
    #[account(mut, seeds = [b"rewy_stake", campaign.key().as_ref()], bump)]
    pub rewy_stake_account: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"airdrop_stake", campaign.key().as_ref()], bump)]
    pub airdrop_stake_account: Option<Account<'info, TokenAccount>>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub clock: Sysvar<'info, Clock>,
}

#[derive(Accounts)]
pub struct UpdateRewards<'info> {
    #[account(mut, has_one = authority)]
    pub campaign: Account<'info, Campaign>,
    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct SubmitProof<'info> {
    #[account(mut, has_one = rewy_stake_account, constraint = campaign.campaign_type == CampaignType::StakeForAction)]
    pub campaign: Account<'info, Campaign>,
    #[account(mut)]
    pub rewy_stake_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub airdrop_stake_account: Option<Account<'info, TokenAccount>>,
    /// CHECK: This is the user's wallet receiving tokens, verified by Ed25519 signature
    #[account(mut)]
    pub user_wallet: AccountInfo<'info>,
    pub token_program: Program<'info, Token>,
    pub clock: Sysvar<'info, Clock>,
    /// CHECK: This is the instructions sysvar for Ed25519 verification
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instructions: UncheckedAccount<'info>,
    #[account(seeds = [b"rewy_ai_config"], bump)]
    pub config: Account<'info, RewyAIConfig>,
}

#[derive(Accounts)]
pub struct RedeemDistribution<'info> {
    #[account(mut, has_one = rewy_stake_account)]
    pub campaign: Account<'info, Campaign>,
    #[account(mut, seeds = [b"rewy_stake", campaign.key().as_ref()], bump)]
    pub rewy_stake_account: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"airdrop_stake", campaign.key().as_ref()], bump)]
    pub airdrop_stake_account: Option<Account<'info, TokenAccount>>,
    #[account(mut, seeds = [b"distribution", campaign.key().as_ref(), distribution.code.as_bytes()], bump)]
    pub distribution: Account<'info, Distribution>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct AirdropParams {
    pub mint: Pubkey,
    pub stake: u64,
    pub reward: u64,
}

// Program
#[program]
pub mod rewy_protocol {
    use super::*;

    pub fn initialize_config(ctx: Context<InitializeConfig>, verifier_key: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.admin = ctx.accounts.admin.key();
        config.verifier_key = verifier_key;
        Ok(())
    }

    pub fn update_verifier_key(ctx: Context<UpdateVerifierKey>, new_key: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.verifier_key = new_key;
        Ok(())
    }

    pub fn initialize_campaign(
        ctx: Context<InitializeCampaign>,
        campaign_type: CampaignType,
        rewy_stake: u64,
        rewy_reward_per_action: u64,
        expiry: Option<i64>,
        max_claims: u64,
        metadata: String,
        content_hash: [u8; 32],
        business_verifier_key: Option<Pubkey>,
        airdrop_params: Option<AirdropParams>,
    ) -> Result<()> {
        let campaign = &mut ctx.accounts.campaign;
        campaign.authority = ctx.accounts.authority.key();
        campaign.pda = campaign.key();
        campaign.campaign_type = campaign_type;
        campaign.rewy_mint = ctx.accounts.rewy_mint.key();
        campaign.rewy_stake_account = ctx.accounts.rewy_stake_account.key();
        campaign.rewy_staked_amount = rewy_stake;
        campaign.expiry = expiry;
        campaign.is_active = true;
        campaign.metadata = metadata;
        campaign.content_hash = content_hash;
        campaign.max_claims = Some(max_claims);
        campaign.nonce = 0;
        campaign.rewy_reward_per_action = rewy_reward_per_action;
        campaign.business_verifier_key = business_verifier_key;

        if let Some(params) = airdrop_params {
            campaign.airdrop_mint = Some(params.mint);
            campaign.airdrop_stake_account = Some(ctx.accounts.airdrop_stake_account.as_ref().unwrap().key());
            campaign.airdrop_staked_amount = Some(params.stake);
            campaign.airdrop_reward_per_action = Some(params.reward);
        }

        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.authority.to_account_info(),
                    to: ctx.accounts.rewy_stake_account.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            rewy_stake,
        )?;

        Ok(())
    }

    pub fn stake_rewards(ctx: Context<StakeRewards>, rewy_amount: u64, airdrop_amount: Option<u64>) -> Result<()> {
        let campaign = &mut ctx.accounts.campaign;
        require!(campaign.is_active, ErrorCode::CampaignPaused);

        token::transfer(CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.authority.to_account_info(),
                to: ctx.accounts.rewy_stake_account.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            },
        ), rewy_amount)?;
        campaign.rewy_staked_amount += rewy_amount;

        if let Some(amount) = airdrop_amount {
            require!(campaign.airdrop_mint.is_some(), ErrorCode::NoAirdropConfigured);
            token::transfer(CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.authority.to_account_info(),
                    to: ctx.accounts.airdrop_stake_account.as_ref().unwrap().to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ), amount)?;
            campaign.airdrop_staked_amount = Some(campaign.airdrop_staked_amount.unwrap() + amount);
        }
        Ok(())
    }

    pub fn unstake_rewards(ctx: Context<UnstakeRewards>, rewy_amount: u64, airdrop_amount: Option<u64>) -> Result<()> {
        let campaign_info = ctx.accounts.campaign.to_account_info();
        let campaign = &mut ctx.accounts.campaign;
        require!(campaign.rewy_staked_amount >= rewy_amount, ErrorCode::InsufficientStake);
        if let Some(lock) = campaign.stake_locked_until {
            require!(ctx.accounts.clock.unix_timestamp >= lock, ErrorCode::StakeLocked);
        }

        campaign.rewy_staked_amount -= rewy_amount;
        if let Some(amount) = airdrop_amount {
            require!(campaign.airdrop_staked_amount.unwrap() >= amount, ErrorCode::InsufficientStake);
            campaign.airdrop_staked_amount = Some(campaign.airdrop_staked_amount.unwrap() - amount);
        }
        if campaign.rewy_staked_amount == 0 {
            campaign.is_active = false;
        }

        let authority_key = ctx.accounts.authority.key();
        let bump = ctx.bumps.rewy_stake_account;
        let seeds = [
            b"campaign" as &[u8],
            authority_key.as_ref(),
            campaign.metadata.as_bytes(),
            &[bump],
        ];
        let signer_seeds = &[&seeds[..]];

        token::transfer(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.rewy_stake_account.to_account_info(),
                to: ctx.accounts.authority.to_account_info(),
                authority: campaign_info.clone(),
            },
            signer_seeds,
        ), rewy_amount)?;

        if let Some(amount) = airdrop_amount {
            token::transfer(CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.airdrop_stake_account.as_ref().unwrap().to_account_info(),
                    to: ctx.accounts.authority.to_account_info(),
                    authority: campaign_info.clone(),
                },
                signer_seeds,
            ), amount)?;
        }

        Ok(())
    }

    pub fn update_rewards(
        ctx: Context<UpdateRewards>,
        new_rewy_reward: u64,
        new_airdrop_reward: Option<u64>,
        new_max_claims: Option<u64>,
    ) -> Result<()> {
        let campaign = &mut ctx.accounts.campaign;
        require!(campaign.is_active, ErrorCode::CampaignPaused);
        require!(
            campaign.rewy_staked_amount >= new_rewy_reward * (campaign.nonce + 1),
            ErrorCode::InsufficientStakeForUpdate
        );

        campaign.rewy_reward_per_action = new_rewy_reward;

        if let Some(amount) = new_airdrop_reward {
            require!(
                campaign.airdrop_staked_amount.is_some() && 
                campaign.airdrop_staked_amount.unwrap() >= amount * (campaign.nonce + 1),
                ErrorCode::InsufficientStakeForUpdate
            );
            campaign.airdrop_reward_per_action = Some(amount);
        } else if campaign.airdrop_mint.is_some() {
            campaign.airdrop_reward_per_action = Some(0);
        }

        if let Some(max) = new_max_claims {
            require!(max >= campaign.nonce, ErrorCode::MaxClaimsTooLow);
            campaign.max_claims = Some(max);
        }

        emit!(RewardsUpdated {
            campaign: campaign.pda,
            rewy_reward: new_rewy_reward,
            airdrop_reward: new_airdrop_reward,
            max_claims: new_max_claims,
        });
        Ok(())
    }

    pub fn submit_proof(ctx: Context<SubmitProof>, proof_code: Vec<u8>) -> Result<()> {
        let campaign_info = ctx.accounts.campaign.to_account_info();
        let campaign = &mut ctx.accounts.campaign;
        require!(campaign.is_active, ErrorCode::CampaignPaused);
        require!(campaign.rewy_staked_amount >= campaign.rewy_reward_per_action, ErrorCode::InsufficientStake);
        if let Some(expiry) = campaign.expiry {
            require!(ctx.accounts.clock.unix_timestamp < expiry, ErrorCode::CampaignExpired);
        }
        if let Some(max) = campaign.max_claims {
            require!(campaign.nonce < max, ErrorCode::MaxClaimsReached);
        }

        let challenge = hash(
            campaign.pda,
            ctx.accounts.user_wallet.key(),
            campaign.nonce,
            campaign.rewy_reward_per_action,
            campaign.airdrop_reward_per_action.unwrap_or(0),
        );
        let message = anchor_lang::solana_program::hash::hash(&challenge).to_bytes();

        // Check REWY AI key (global) and business key (campaign-specific)
        let rewy_ai_key = ctx.accounts.config.verifier_key;
        let verifier_keys = [
            Some(rewy_ai_key),
            campaign.business_verifier_key,
        ];
        let mut signature_valid = false;
        for verifier_key in verifier_keys.iter().flatten() {
            let ed25519_ix = Instruction {
                program_id: anchor_lang::solana_program::ed25519_program::ID,
                accounts: vec![],
                data: [
                    vec![0u8],
                    verifier_key.to_bytes().to_vec(),
                    proof_code.clone(),
                    message.to_vec(),
                ].concat(),
            };
            let result = anchor_lang::solana_program::program::invoke(
                &ed25519_ix,
                &[ctx.accounts.user_wallet.clone(), ctx.accounts.instructions.to_account_info()],
            );
            if result.is_ok() {
                signature_valid = true;
                break;
            }
        }
        require!(signature_valid, ErrorCode::InvalidProof);

        campaign.rewy_staked_amount -= campaign.rewy_reward_per_action;
        let mut airdrop_amount = None;
        if let Some(amount) = campaign.airdrop_reward_per_action {
            if amount > 0 && campaign.airdrop_staked_amount.unwrap() >= amount {
                campaign.airdrop_staked_amount = Some(campaign.airdrop_staked_amount.unwrap() - amount);
                airdrop_amount = Some(amount);
            }
        }
        campaign.nonce += 1;

        let seeds = [b"campaign", campaign.authority.as_ref(), campaign.metadata.as_bytes()];
        let signer_seeds = &[&seeds[..]];

        token::transfer(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.rewy_stake_account.to_account_info(),
                to: ctx.accounts.user_wallet.to_account_info(),
                authority: campaign_info.clone(),
            },
            signer_seeds,
        ), campaign.rewy_reward_per_action)?;

        if let Some(amount) = airdrop_amount {
            token::transfer(CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.airdrop_stake_account.as_ref().unwrap().to_account_info(),
                    to: ctx.accounts.user_wallet.to_account_info(),
                    authority: campaign_info.clone(),
                },
                signer_seeds,
            ), amount)?;
        }

        emit!(ClaimMade {
            campaign: campaign.pda,
            user: ctx.accounts.user_wallet.key(),
            rewy_amount: campaign.rewy_reward_per_action,
            airdrop_amount,
            claims_remaining: campaign.max_claims.map(|max| max - campaign.nonce),
        });
        Ok(())
    }

    pub fn redeem_voucher(
        ctx: Context<RedeemVoucher>,
        voucher: Vec<u8>,
        rewy_amount: u64,
        airdrop_amount: Option<u64>,
    ) -> Result<()> {
        let campaign_info = ctx.accounts.campaign.to_account_info();
        let campaign = &mut ctx.accounts.campaign;
        require!(campaign.is_active, ErrorCode::CampaignPaused);
        require!(campaign.rewy_staked_amount >= rewy_amount, ErrorCode::InsufficientStake);
        if let Some(amount) = airdrop_amount {
            require!(campaign.airdrop_staked_amount.unwrap() >= amount, ErrorCode::InsufficientStake);
        }
        if let Some(expiry) = campaign.expiry {
            require!(ctx.accounts.clock.unix_timestamp < expiry, ErrorCode::CampaignExpired);
        }
        if let Some(max) = campaign.max_claims {
            require!(campaign.nonce < max, ErrorCode::MaxClaimsReached);
        }

        let challenge = hash(
            campaign.pda,
            ctx.accounts.user_wallet.key(),
            campaign.nonce,
            rewy_amount,
            airdrop_amount.unwrap_or(0),
        );
        let message = anchor_lang::solana_program::hash::hash(&challenge).to_bytes();

        let rewy_ai_key = ctx.accounts.config.verifier_key;
        let verifier_keys = [
            Some(rewy_ai_key),
            campaign.business_verifier_key,
        ];
        let mut signature_valid = false;
        for verifier_key in verifier_keys.iter().flatten() {
            let ed25519_ix = Instruction {
                program_id: anchor_lang::solana_program::ed25519_program::ID,
                accounts: vec![],
                data: [
                    vec![0u8],
                    verifier_key.to_bytes().to_vec(),
                    voucher.clone(),
                    message.to_vec(),
                ].concat(),
            };
            let result = anchor_lang::solana_program::program::invoke(
                &ed25519_ix,
                &[ctx.accounts.user_wallet.clone(), ctx.accounts.instructions.to_account_info()],
            );
            if result.is_ok() {
                signature_valid = true;
                break;
            }
        }
        require!(signature_valid, ErrorCode::InvalidProof);

        campaign.rewy_staked_amount -= rewy_amount;
        if let Some(amount) = airdrop_amount {
            campaign.airdrop_staked_amount = Some(campaign.airdrop_staked_amount.unwrap() - amount);
        }
        campaign.nonce += 1;

        let seeds = [b"campaign", campaign.authority.as_ref(), campaign.metadata.as_bytes()];
        let signer_seeds = &[&seeds[..]];

        token::transfer(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.rewy_stake_account.to_account_info(),
                to: ctx.accounts.user_wallet.to_account_info(),
                authority: campaign_info.clone(),
            },
            signer_seeds,
        ), rewy_amount)?;

        if let Some(amount) = airdrop_amount {
            token::transfer(CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.airdrop_stake_account.as_ref().unwrap().to_account_info(),
                    to: ctx.accounts.user_wallet.to_account_info(),
                    authority: campaign_info.clone(),
                },
                signer_seeds,
            ), amount)?;
        }

        emit!(ClaimMade {
            campaign: campaign.pda,
            user: ctx.accounts.user_wallet.key(),
            rewy_amount,
            airdrop_amount,
            claims_remaining: campaign.max_claims.map(|max| max - campaign.nonce),
        });
        Ok(())
    }

    pub fn redeem_distribution(ctx: Context<RedeemDistribution>) -> Result<()> {
        let campaign_info = ctx.accounts.campaign.to_account_info();
        let campaign = &mut ctx.accounts.campaign;
        let distribution = &mut ctx.accounts.distribution;
        require!(!distribution.is_redeemed, ErrorCode::AlreadyRedeemed);
        require!(campaign.rewy_staked_amount >= distribution.rewy_amount, ErrorCode::InsufficientStake);
        if let Some(amount) = distribution.airdrop_amount {
            require!(campaign.airdrop_staked_amount.unwrap() >= amount, ErrorCode::InsufficientStake);
        }

        campaign.rewy_staked_amount -= distribution.rewy_amount;
        if let Some(amount) = distribution.airdrop_amount {
            campaign.airdrop_staked_amount = Some(campaign.airdrop_staked_amount.unwrap() - amount);
        }
        distribution.is_redeemed = true;
        distribution.recipient = Some(ctx.accounts.user.key());

        let bump = ctx.bumps.rewy_stake_account;
        let seeds = [
            b"campaign" as &[u8],
            campaign.authority.as_ref(),
            campaign.metadata.as_bytes(),
            &[bump],
        ];
        let signer_seeds = &[&seeds[..]];

        token::transfer(CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            token::Transfer {
                from: ctx.accounts.rewy_stake_account.to_account_info(),
                to: ctx.accounts.user.to_account_info(),
                authority: campaign_info.clone(),
            },
            signer_seeds,
        ), distribution.rewy_amount)?;

        if let Some(amount) = distribution.airdrop_amount {
            token::transfer(CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.airdrop_stake_account.as_ref().unwrap().to_account_info(),
                    to: ctx.accounts.user.to_account_info(),
                    authority: campaign_info.clone(),
                },
                signer_seeds,
            ), amount)?;
        }

        emit!(DistributionRedeemed {
            campaign: campaign.pda,
            code: distribution.code.clone(),
            recipient: ctx.accounts.user.key(),
        });
        Ok(())
    }
}

fn hash(pda: Pubkey, user: Pubkey, nonce: u64, rewy_amount: u64, airdrop_amount: u64) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(pda.as_ref());
    hasher.update(user.as_ref());
    hasher.update(nonce.to_le_bytes());
    hasher.update(rewy_amount.to_le_bytes());
    hasher.update(airdrop_amount.to_le_bytes());
    hasher.finalize().to_vec()
}
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { RewyProtocol } from "../target/types/rewy_protocol";

describe("rewy_protocol", () => {
  // Configure the client to use the local cluster.
  anchor.setProvider(anchor.AnchorProvider.env());

  const program = anchor.workspace.RewyProtocol as Program<RewyProtocol>;

  it("Is initialized!", async () => {
    // Add your test here.
    const tx = await program.methods.initializeCampaign
    console.log("Your transaction signature", tx);
  });
});

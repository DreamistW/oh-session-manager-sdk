/*
 * Copyright (c) 2026 HomoXterm contributors.
 * Licensed under the Apache License, Version 2.0.
 */

export class TelnetDecodeResult {
  readonly data: number[];
  readonly reply: number[];

  constructor(data: number[], reply: number[]) {
    this.data = data;
    this.reply = reply;
  }
}

enum TelnetParseState {
  Data,
  Command,
  Negotiation,
  SubOption,
  SubData,
  SubCommand
}

export class TelnetCodec {
  private static readonly IAC: number = 255;
  private static readonly DONT: number = 254;
  private static readonly DO: number = 253;
  private static readonly WONT: number = 252;
  private static readonly WILL: number = 251;
  private static readonly SB: number = 250;
  private static readonly SE: number = 240;
  private static readonly BINARY: number = 0;
  private static readonly ECHO: number = 1;
  private static readonly SUPPRESS_GO_AHEAD: number = 3;
  private static readonly TERMINAL_TYPE: number = 24;
  private static readonly WINDOW_SIZE: number = 31;
  private state: TelnetParseState = TelnetParseState.Data;
  private negotiationCommand: number = 0;
  private subOption: number = 0;
  private subData: number[] = [];
  private previousWasCarriageReturn: boolean = false;

  decode(bytes: Uint8Array): TelnetDecodeResult {
    const data: number[] = [];
    const reply: number[] = [];
    for (let index = 0; index < bytes.length; index++) {
      this.consumeByte(bytes[index], data, reply);
    }
    return new TelnetDecodeResult(data, reply);
  }

  encode(bytes: Uint8Array): Uint8Array {
    const output: number[] = [];
    bytes.forEach((value: number): void => {
      output.push(value);
      if (value === TelnetCodec.IAC) {
        output.push(value);
      }
    });
    return new Uint8Array(output);
  }

  windowSize(columns: number, rows: number): Uint8Array {
    const width = Math.max(1, Math.min(65535, Math.floor(columns)));
    const height = Math.max(1, Math.min(65535, Math.floor(rows)));
    return new Uint8Array([TelnetCodec.IAC, TelnetCodec.SB, TelnetCodec.WINDOW_SIZE,
      (width >> 8) & 0xff, width & 0xff, (height >> 8) & 0xff, height & 0xff,
      TelnetCodec.IAC, TelnetCodec.SE]);
  }

  private consumeByte(value: number, data: number[], reply: number[]): void {
    if (this.state === TelnetParseState.Data) {
      if (value === TelnetCodec.IAC) {
        this.state = TelnetParseState.Command;
      } else if (!(this.previousWasCarriageReturn && value === 0)) {
        data.push(value);
      }
      this.previousWasCarriageReturn = value === 13;
      return;
    }
    this.previousWasCarriageReturn = false;
    if (this.state === TelnetParseState.Command) {
      if (value === TelnetCodec.IAC) {
        data.push(value);
        this.state = TelnetParseState.Data;
      } else if (value === TelnetCodec.DO || value === TelnetCodec.DONT ||
        value === TelnetCodec.WILL || value === TelnetCodec.WONT) {
        this.negotiationCommand = value;
        this.state = TelnetParseState.Negotiation;
      } else if (value === TelnetCodec.SB) {
        this.state = TelnetParseState.SubOption;
      } else {
        this.state = TelnetParseState.Data;
      }
      return;
    }
    if (this.state === TelnetParseState.Negotiation) {
      this.negotiate(this.negotiationCommand, value, reply);
      this.state = TelnetParseState.Data;
      return;
    }
    if (this.state === TelnetParseState.SubOption) {
      this.subOption = value;
      this.subData = [];
      this.state = TelnetParseState.SubData;
      return;
    }
    if (this.state === TelnetParseState.SubData) {
      if (value === TelnetCodec.IAC) {
        this.state = TelnetParseState.SubCommand;
      } else {
        this.subData.push(value);
      }
      return;
    }
    if (value === TelnetCodec.SE) {
      this.finishSubnegotiation(reply);
      this.state = TelnetParseState.Data;
    } else {
      if (value === TelnetCodec.IAC) {
        this.subData.push(value);
      }
      this.state = TelnetParseState.SubData;
    }
  }

  private negotiate(command: number, option: number, reply: number[]): void {
    if (command === TelnetCodec.WILL) {
      const accepted = option === TelnetCodec.BINARY || option === TelnetCodec.ECHO ||
        option === TelnetCodec.SUPPRESS_GO_AHEAD;
      reply.push(TelnetCodec.IAC, accepted ? TelnetCodec.DO : TelnetCodec.DONT, option);
    } else if (command === TelnetCodec.DO) {
      const accepted = option === TelnetCodec.BINARY || option === TelnetCodec.SUPPRESS_GO_AHEAD ||
        option === TelnetCodec.TERMINAL_TYPE || option === TelnetCodec.WINDOW_SIZE;
      reply.push(TelnetCodec.IAC, accepted ? TelnetCodec.WILL : TelnetCodec.WONT, option);
    }
  }

  private finishSubnegotiation(reply: number[]): void {
    if (this.subOption !== TelnetCodec.TERMINAL_TYPE || this.subData.length === 0 || this.subData[0] !== 1) {
      return;
    }
    const terminal = 'xterm-256color';
    reply.push(TelnetCodec.IAC, TelnetCodec.SB, TelnetCodec.TERMINAL_TYPE, 0);
    for (let index = 0; index < terminal.length; index++) {
      reply.push(terminal.charCodeAt(index));
    }
    reply.push(TelnetCodec.IAC, TelnetCodec.SE);
  }
}

/*
* Windbg extension for VM traffic manipulation and analysis
* 
* Copyright 2011, isciurus. All rights reserved.
* 
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:
* 
* - Redistributions of source code must retain the above copyright notice, this
*   list of conditions and the following disclaimer.
*
* - Redistributions in binary form must reproduce the above copyright notice, this
*   list of conditions and the following disclaimer in the documentation and/or
*   other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
* INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
* BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
* OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
* OF THE POSSIBILITY OF SUCH DAMAGE.
*
*/

#include "windows.h"

#include "../dbgexts.h"

#include "windbgshark.h"

#include "mutate.h"


HRESULT Mutator::setMutator(ULONG id, PCHAR scriptFileName, PCHAR filter)
{
	_id = id;

	_filter = NULL;
	if(filter != NULL && strlen(filter) != 0)
	{
		_filter = new CHAR[strlen(filter) + 1];
		ZeroMemory(_filter, strlen(filter) + 1);
		RtlCopyMemory(_filter, filter, strlen(filter));
	}

	_scriptFileName = NULL;
	if(scriptFileName != NULL && strlen(scriptFileName) != 0)
	{
		_scriptFileName = new CHAR[strlen(scriptFileName) + 1];
		ZeroMemory(_scriptFileName, strlen(scriptFileName) + 1);
		RtlCopyMemory(_scriptFileName, scriptFileName, strlen(scriptFileName));
	}

	return S_OK;
}

Mutator::~Mutator()
{
	if(_filter != NULL)
	{
		delete [] _filter;
	}

	if(_scriptFileName != NULL)
	{
		delete [] _scriptFileName;
	}
}

HRESULT Mutator::printMutator()
{
	dprintf("%d \t %s \t %s\n",
		this->_id, this->_scriptFileName, this->_filter);

	return S_OK;
}


MutationEngine::~MutationEngine()
{
	mutatorsMap::iterator mutatorIt;
	ULONG mutatorId;
	for(mutatorIt = _mutators.begin(), mutatorId = 0; 
		mutatorIt != _mutators.end(); 
		mutatorIt++, mutatorId++)
	{
		if((*mutatorIt).second != NULL)
		{
			delete (*mutatorIt).second;
		}
	}
}

HRESULT MutationEngine::printMutators()
{
	dprintf("<id> \t <script> \t\t\t\t <filter>\n");

	mutatorsMap::iterator mutatorIt;
	ULONG mutatorId;
	for(mutatorIt = _mutators.begin(), mutatorId = 0; 
		mutatorIt != _mutators.end(); 
		mutatorIt++, mutatorId++)
	{
		if((*mutatorIt).second != NULL)
		{
			(*mutatorIt).second->printMutator();
		}
	}

	return S_OK;
}

HRESULT MutationEngine::addMutator(PCHAR scriptFileName, PCHAR filter)
{
	if(_mutators.size() >= this->_maxMutatorsNum)
	{
		dprintf("[windbgshark] MutationEngine::addMutator: sorry, mutators number reached _maxMutatorsNum = %d\n", this->_maxMutatorsNum);
		return E_FAIL;
	}

	Mutator *pMutator = new Mutator();
	if(pMutator == NULL)
	{
		dprintf("[windbgshark] MutationEngine::addMutator: error! could not allocate memory for a new mutator\n");
		return E_FAIL;
	}

	ULONG mutatorId;
	for(mutatorId = 0; mutatorId < this->_maxMutatorsNum; mutatorId++)
	{
		if(_mutators.find(mutatorId) == _mutators.end())
		{
			break;
		}
	}

	if(mutatorId >= this->_maxMutatorsNum)
	{
		dprintf("[windbgshark] MutationEngine::addMutator: error! could not find suitable Id for mutator\n");
		return E_FAIL;
	}

	pMutator->setMutator(mutatorId, filter, scriptFileName);

	_mutators[mutatorId] = pMutator;

	return S_OK;
}

HRESULT MutationEngine::removeMutatorById(ULONG mutatorId)
{
	mutatorsMap::iterator removedMutatorIt = _mutators.find(mutatorId);
	if(removedMutatorIt != _mutators.end())
	{
		delete removedMutatorIt->second;
		_mutators.erase(removedMutatorIt);

		return S_OK;
	}

	return E_FAIL;
}